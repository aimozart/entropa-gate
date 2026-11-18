//! Bounded line reader for the stdio edge. MCP stdio is newline-delimited, so a request is one
//! line. This copies stdin to the protocol layer line by line, but never buffers more than
//! `max_line_bytes` of one line: an over-long line is dropped and replaced by a small request that
//! the protocol layer answers with an error naming `entropa/request_too_large`, so memory stays
//! bounded and the server keeps working.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Largest accepted request line: 1 MiB.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

const REPLACEMENT: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":\"request_too_large\",\"method\":\"entropa/request_too_large\"}\n";

/// Copy `input` to `output` line by line, replacing any line longer than `max_line_bytes`.
/// Returns when `input` ends (the caller then drops `output`, which ends the protocol session).
pub async fn pump_bounded<R, W>(
    input: R,
    mut output: W,
    max_line_bytes: usize,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::with_capacity(8 * 1024, input);
    let mut line: Vec<u8> = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            // end of input: flush a final line that had no trailing newline
            if too_long {
                output.write_all(REPLACEMENT).await?;
            } else if !line.is_empty() {
                line.push(b'\n');
                output.write_all(&line).await?;
            }
            output.flush().await?;
            return Ok(());
        }
        let (take, found_newline) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !too_long {
            let body = if found_newline { take - 1 } else { take };
            if line.len() + body > max_line_bytes {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(&chunk[..body]);
            }
        }
        reader.consume(take);
        if found_newline {
            if too_long {
                output.write_all(REPLACEMENT).await?;
            } else {
                line.push(b'\n');
                output.write_all(&line).await?;
            }
            output.flush().await?;
            line.clear();
            too_long = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(input: &[u8], max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        pump_bounded(input, &mut out, max).await.unwrap();
        out
    }

    #[tokio::test]
    async fn short_lines_pass_through_unchanged() {
        assert_eq!(run(b"abc\ndef\n", 10).await, b"abc\ndef\n");
    }

    #[tokio::test]
    async fn a_line_of_exactly_the_limit_passes_and_one_more_byte_is_replaced() {
        assert_eq!(run(b"12345\n", 5).await, b"12345\n");
        assert_eq!(
            run(b"123456\nok\n", 5).await,
            [REPLACEMENT, b"ok\n"].concat()
        );
    }

    #[tokio::test]
    async fn a_final_line_without_a_newline_is_flushed_with_one() {
        assert_eq!(run(b"abc", 10).await, b"abc\n");
        assert_eq!(run(b"abcdefghijkl", 5).await, REPLACEMENT);
    }

    #[tokio::test]
    async fn memory_stays_bounded_for_a_huge_line() {
        let huge = vec![b'x'; 5 * 1024 * 1024];
        let mut input = huge;
        input.extend_from_slice(b"\nnext\n");
        assert_eq!(run(&input, 1024).await, [REPLACEMENT, b"next\n"].concat());
    }
}
