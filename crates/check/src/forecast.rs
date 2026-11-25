//! The forecast `entropa-forecast-v1`.
use crate::Refusal;

/// A bar on a metric.
#[derive(Debug, Clone, PartialEq)]
pub struct Bar {
    /// One of `<=`, `<`, `>=`, `>`.
    pub op: String,
    /// The threshold.
    pub value: f64,
}

/// One forecast metric.
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// The closed metric name.
    pub name: String,
    /// The low end of the forecast range.
    pub low: f64,
    /// The central guess.
    pub central: f64,
    /// The high end of the forecast range.
    pub high: f64,
    /// An optional bar.
    pub bar: Option<Bar>,
}

/// A parsed forecast.
#[derive(Debug, Clone, PartialEq)]
pub struct Forecast {
    /// The stage id.
    pub stage: String,
    /// The metrics.
    pub metrics: Vec<Metric>,
}

/// Is this a closed metric name?
fn metric_ok(n: &str) -> bool {
    if matches!(n, "failed_rate" | "accepted_attacks" | "failed") {
        return true;
    }
    n.strip_prefix("class:")
        .and_then(|r| r.strip_suffix(":failed_rate"))
        .is_some_and(crate::name_ok)
}

/// Parse and validate a forecast.
pub fn parse(bytes: &[u8]) -> Result<Forecast, Refusal> {
    if bytes.len() > 1024 * 1024 {
        return Err(Refusal::new("the forecast is larger than 1 MiB"));
    }
    let v = crate::strict(bytes)?;
    let o = v
        .as_object()
        .ok_or_else(|| Refusal::new("the forecast is not an object"))?;
    if o.keys()
        .any(|k| !matches!(k.as_str(), "schema" | "stage" | "written" | "metrics"))
    {
        return Err(Refusal::new("the forecast has a field outside the schema"));
    }
    if o.get("schema").and_then(|s| s.as_str()) != Some("entropa-forecast-v1") {
        return Err(Refusal::new("the schema is not entropa-forecast-v1"));
    }
    let stage = o
        .get("stage")
        .and_then(|s| s.as_str())
        .filter(|s| crate::name_ok(s))
        .ok_or_else(|| Refusal::new("the stage is missing or outside the pattern"))?;
    if !o
        .get("written")
        .and_then(|w| w.as_str())
        .is_some_and(|w| !w.is_empty() && w.len() <= 40)
    {
        return Err(Refusal::new("written must be a short text"));
    }
    let list = o
        .get("metrics")
        .and_then(|m| m.as_array())
        .filter(|m| !m.is_empty() && m.len() <= 200)
        .ok_or_else(|| Refusal::new("the forecast needs 1 to 200 metrics"))?;
    let mut metrics = Vec::new();
    for (i, m) in list.iter().enumerate() {
        let bad = |t: &str| Refusal(format!("metric #{i}: {t}"));
        let mo = m.as_object().ok_or_else(|| bad("not an object"))?;
        if mo
            .keys()
            .any(|k| !matches!(k.as_str(), "name" | "low" | "central" | "high" | "bar"))
        {
            return Err(bad("a field outside the schema"));
        }
        let name = mo
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| metric_ok(n))
            .ok_or_else(|| bad("the name is not on the closed list"))?;
        let num = |k: &str| {
            mo.get(k)
                .and_then(|x| x.as_f64())
                .filter(|x| x.is_finite() && *x >= 0.0)
                .ok_or_else(|| bad("low, central and high must be non-negative numbers"))
        };
        let (low, central, high) = (num("low")?, num("central")?, num("high")?);
        if !(low <= central && central <= high) {
            return Err(bad("low <= central <= high is required"));
        }
        let bar = match mo.get("bar") {
            None => None,
            Some(b) => {
                let bo = b
                    .as_object()
                    .ok_or_else(|| bad("the bar is not an object"))?;
                if bo.keys().any(|k| k != "op" && k != "value") {
                    return Err(bad("the bar has a field outside the schema"));
                }
                let op = bo
                    .get("op")
                    .and_then(|x| x.as_str())
                    .filter(|x| matches!(*x, "<=" | "<" | ">=" | ">"))
                    .ok_or_else(|| bad("the bar operator is not <=, <, >= or >"))?;
                let value = bo
                    .get("value")
                    .and_then(|x| x.as_f64())
                    .filter(|x| x.is_finite())
                    .ok_or_else(|| bad("the bar value is not a number"))?;
                Some(Bar {
                    op: op.to_string(),
                    value,
                })
            }
        };
        metrics.push(Metric {
            name: name.to_string(),
            low,
            central,
            high,
            bar,
        });
    }
    Ok(Forecast {
        stage: stage.to_string(),
        metrics,
    })
}
