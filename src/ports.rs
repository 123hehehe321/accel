use anyhow::{anyhow, Context, Result};

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedPorts {
    pub singles: Vec<u16>,
    pub ranges: Vec<(u16, u16)>,
}

impl ParsedPorts {
    /// Iterate every individual port covered by this spec (singles first,
    /// then ranges expanded). Used to populate the per-port bitmap in the
    /// eBPF program.
    pub fn iter_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.singles
            .iter()
            .copied()
            .chain(self.ranges.iter().flat_map(|&(lo, hi)| lo..=hi))
    }
}

pub fn parse(spec: &str) -> Result<ParsedPorts> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("ports spec is empty"));
    }

    let mut singles = Vec::new();
    let mut ranges = Vec::new();

    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(anyhow!(
                "empty port entry in '{spec}' (check for stray commas)"
            ));
        }
        match token.split_once('-') {
            Some((lo_s, hi_s)) => {
                let lo = parse_port(lo_s.trim(), token)?;
                let hi = parse_port(hi_s.trim(), token)?;
                if lo > hi {
                    return Err(anyhow!(
                        "invalid range '{token}': lo ({lo}) greater than hi ({hi})"
                    ));
                }
                ranges.push((lo, hi));
            }
            None => {
                singles.push(parse_port(token, token)?);
            }
        }
    }

    Ok(ParsedPorts { singles, ranges })
}

fn parse_port(s: &str, context_token: &str) -> Result<u16> {
    if s.is_empty() {
        return Err(anyhow!(
            "malformed range '{context_token}': missing port number"
        ));
    }
    s.parse::<u16>().with_context(|| {
        format!("invalid port '{s}' in '{context_token}' (expected 0-65535)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_port() {
        let p = parse("443").unwrap();
        assert_eq!(p.singles, vec![443]);
        assert!(p.ranges.is_empty());
        assert_eq!(p.iter_ports().collect::<Vec<_>>(), vec![443]);
    }

    #[test]
    fn multi_singles_and_whitespace() {
        let p = parse(" 443 , 8443,10443 ").unwrap();
        assert_eq!(p.singles, vec![443, 8443, 10443]);
    }

    #[test]
    fn ranges_and_mixed() {
        let p = parse("443,5000-5002,30000-30001").unwrap();
        assert_eq!(p.singles, vec![443]);
        assert_eq!(p.ranges, vec![(5000, 5002), (30000, 30001)]);
        assert_eq!(
            p.iter_ports().collect::<Vec<_>>(),
            vec![443, 5000, 5001, 5002, 30000, 30001]
        );
    }

    #[test]
    fn rejects_bad_numbers_and_ranges() {
        // not a number
        assert!(parse("abc").unwrap_err().to_string().contains("invalid port"));
        // out of u16 range
        assert!(parse("70000")
            .unwrap_err()
            .to_string()
            .contains("invalid port"));
        // range with lo > hi
        assert!(parse("443-100")
            .unwrap_err()
            .to_string()
            .contains("greater than"));
        // malformed range: missing hi
        assert!(parse("443-")
            .unwrap_err()
            .to_string()
            .contains("missing port"));
    }

    #[test]
    fn rejects_empty_and_stray_commas() {
        assert!(parse("").unwrap_err().to_string().contains("empty"));
        assert!(parse("   ").unwrap_err().to_string().contains("empty"));
        assert!(parse("443,,8443")
            .unwrap_err()
            .to_string()
            .contains("empty port entry"));
    }
}
