//! The history filter as the desktop UI describes it.

use mineburp_core::{Direction, Disposition, FilterExpression, ProtocolState, TrafficSource};
use mineburp_project::{ContentMode, ContentQuery, ContentScope, PacketQuery, SearchTerm};
use serde::Deserialize;
use uuid::Uuid;

/// The history filter as the webview describes it.
///
/// One serialisable object rather than a dozen command arguments: the filter
/// grew past the point where positional parameters stayed readable, and the UI
/// already keeps it as a single piece of state.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_excessive_bools)]
pub struct PacketFilterInput {
    connection_id: Option<Uuid>,
    offset: usize,
    limit: usize,
    search: Option<String>,
    search_regex: bool,
    search_case_sensitive: bool,
    search_negate: bool,
    directions: Vec<Direction>,
    states: Vec<ProtocolState>,
    sources: Vec<TrafficSource>,
    dispositions: Vec<Disposition>,
    include_names: Vec<String>,
    exclude_names: Vec<String>,
    min_size: Option<usize>,
    max_size: Option<usize>,
    /// The operator's filter expression, in the same language replacement rules use.
    expression: Option<String>,
    /// A search through the payload bytes rather than the row's metadata.
    content: Option<String>,
    content_mode: ContentSearchMode,
    content_scope: ContentSearchScope,
    content_case_sensitive: bool,
    content_negate: bool,
    before_id: Option<i64>,
    after_id: Option<i64>,
    /// Only bookmarked rows (`true`) or only rows without a bookmark (`false`).
    bookmarked: Option<bool>,
    /// The whole result oldest first; see `PacketQuery::oldest_first`.
    oldest_first: bool,
}

/// How the webview labels the payload-search modes.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSearchMode {
    #[default]
    Text,
    Hex,
    Regex,
}

impl From<ContentSearchMode> for ContentMode {
    fn from(mode: ContentSearchMode) -> Self {
        match mode {
            ContentSearchMode::Text => Self::Text,
            ContentSearchMode::Hex => Self::Hex,
            ContentSearchMode::Regex => Self::Regex,
        }
    }
}

/// How much of the payload the term has to account for.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSearchScope {
    #[default]
    Contains,
    Equals,
    Prefix,
    Suffix,
}

impl From<ContentSearchScope> for ContentScope {
    fn from(scope: ContentSearchScope) -> Self {
        match scope {
            ContentSearchScope::Contains => Self::Contains,
            ContentSearchScope::Equals => Self::Equals,
            ContentSearchScope::Prefix => Self::Prefix,
            ContentSearchScope::Suffix => Self::Suffix,
        }
    }
}

impl PacketFilterInput {
    pub fn into_query(self) -> Result<PacketQuery, String> {
        let expression = self
            .expression
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(FilterExpression::parse)
            .transpose()
            .map_err(|error| error.to_string())?;
        let search = self
            .search
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .map(|text| SearchTerm {
                text,
                regex: self.search_regex,
                case_sensitive: self.search_case_sensitive,
                negate: self.search_negate,
            });
        let content = self
            .content
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .map(|text| ContentQuery {
                text,
                mode: self.content_mode.into(),
                scope: self.content_scope.into(),
                case_sensitive: self.content_case_sensitive,
                negate: self.content_negate,
            });
        Ok(PacketQuery {
            connection_id: self.connection_id,
            offset: self.offset,
            // Fetching an extra row lets the renderer show an exact "load
            // older" affordance without asking SQLite for a total on every
            // live refresh.
            limit: self.limit.clamp(1, 500),
            search,
            directions: self.directions,
            states: self.states,
            sources: self.sources,
            dispositions: self.dispositions,
            include_names: self.include_names,
            exclude_names: self.exclude_names,
            min_size: self.min_size,
            max_size: self.max_size,
            expression,
            content,
            before_id: self.before_id,
            after_id: self.after_id,
            bookmarked: self.bookmarked,
            oldest_first: self.oldest_first,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PacketFilterInput;

    fn filter_from(json: &str) -> PacketFilterInput {
        serde_json::from_str(json).expect("the webview's filter shape must deserialize")
    }

    #[test]
    fn an_empty_filter_object_is_a_complete_filter() {
        let query = filter_from("{}").into_query().expect("empty filter");
        assert!(query.search.is_none());
        assert!(query.expression.is_none());
        assert!(query.states.is_empty() && query.directions.is_empty());
        // Every list defaulting to empty is what makes "no filter" mean "everything".
        assert_eq!(query.limit, 1, "an unset limit is clamped into range");
    }

    #[test]
    fn search_switches_and_enum_sets_survive_the_boundary() {
        let query = filter_from(
            r#"{
                "search": "  keep_alive  ",
                "searchRegex": true,
                "searchCaseSensitive": true,
                "searchNegate": true,
                "states": ["play", "configuration"],
                "dispositions": ["dropped"],
                "excludeNames": ["chunk"],
                "minSize": 16,
                "limit": 250
            }"#,
        )
        .into_query()
        .expect("filter");
        let search = query.search.expect("a search term");
        assert_eq!(
            search.text, "keep_alive",
            "surrounding space is not part of the term"
        );
        assert!(search.regex && search.case_sensitive && search.negate);
        assert_eq!(query.states.len(), 2);
        assert_eq!(query.dispositions.len(), 1);
        assert_eq!(query.exclude_names, vec!["chunk".to_owned()]);
        assert_eq!(query.min_size, Some(16));
        assert_eq!(query.limit, 250);
    }

    #[test]
    fn a_blank_search_or_expression_is_dropped_rather_than_matched() {
        let query = filter_from(r#"{"search": "   ", "expression": "  "}"#)
            .into_query()
            .expect("filter");
        assert!(query.search.is_none());
        assert!(query.expression.is_none());
    }

    #[test]
    fn an_unparseable_expression_is_reported_to_the_operator() {
        let error = filter_from(r#"{"expression": "state !! play"}"#)
            .into_query()
            .expect_err("an unknown operator must be rejected");
        assert!(
            error.contains("operator"),
            "the message should name the problem, got `{error}`"
        );
    }

    #[test]
    fn a_payload_search_carries_its_mode_across_the_boundary() {
        let query = filter_from(
            r#"{"content": " de ad be ef ", "contentMode": "hex", "contentNegate": true}"#,
        )
        .into_query()
        .expect("filter");
        let content = query.content.expect("a content search");
        assert_eq!(content.text, "de ad be ef");
        assert!(content.negate);
        assert!(matches!(content.mode, mineburp_project::ContentMode::Hex));
        assert!(
            matches!(content.scope, mineburp_project::ContentScope::Contains),
            "an unstated scope stays the substring search it has always been"
        );

        let scoped =
            filter_from(r#"{"content": "0c", "contentMode": "hex", "contentScope": "equals"}"#)
                .into_query()
                .expect("filter");
        assert!(matches!(
            scoped.content.expect("a content search").scope,
            mineburp_project::ContentScope::Equals
        ));
    }

    #[test]
    fn a_blank_payload_search_is_dropped() {
        let query = filter_from(r#"{"content": "  ", "contentMode": "regex"}"#)
            .into_query()
            .expect("filter");
        assert!(
            query.content.is_none(),
            "a blank term must not scan payloads"
        );
    }

    #[test]
    fn a_valid_expression_reaches_the_query() {
        let query = filter_from(r#"{"expression": "state == play && size > 256"}"#)
            .into_query()
            .expect("filter");
        assert!(query.expression.is_some());
    }

    #[test]
    fn the_bookmark_filter_reaches_the_query() {
        let query = filter_from(r#"{"bookmarked": true}"#)
            .into_query()
            .expect("filter");
        assert_eq!(query.bookmarked, Some(true));
    }
}
