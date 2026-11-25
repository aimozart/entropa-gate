# The dashboard

**Status: in progress.** Built and tested locally on a mock feed; not hosted yet.

## What it shows
A single page next to the record explorer. It shows counts, nothing else about the records themselves:
- the total number of records and the head checkpoint (size and root);
- records by outcome, by kind, by reason, by control and by label;
- records per day (UTC) for the latest 60 days, and one total for earlier days ("Earlier days: N days, M records");
- the ten newest records as one plain sentence each.

## The data is mock, the signatures are real
Every file carries the line **mock data, real signed records**. The traffic comes from a seeded generator, the signing key is a throwaway key made for the demonstration, and nothing is production or customer data. The records themselves are really signed and were verified offline before the page was written.

## The page checks its own numbers
The page does not just display a summary. It loads every record page, counts the records again in your browser and compares its result with the summary file. If any number differs, a notice appears: "The numbers on this page do not match the data files. Do not rely on them." (A test changes one number on purpose and checks that the notice appears.)

## How to check the records themselves
The dashboard does not verify signatures in the browser. It shows the exact command to run on your own copy of the ledger. (The separate browser checker verifies bundles in the browser; the format of this explorer's ledger copy is not yet supported by it.)

## Numbers from the build
For a 10,000-record feed the whole bundle is 5.9 MB in 54 files; the dashboard itself adds three small files. In headless Chrome the page rendered in about 0.12 seconds on the test machine.

## Honest limits
- Mock data only until it is pointed at a real feed.
- Counts are shown as bars and numbers; there is no time-series chart beyond the per-day list.
- One browser (Chrome) on one machine has been tested.
- The page proves nothing about the records by itself; the command above does.
