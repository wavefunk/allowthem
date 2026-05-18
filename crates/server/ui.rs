use std::fmt;

use wavefunk_ui::Template;
pub use wavefunk_ui::components::{HtmlAttr, TrustedHtml};

pub type UiRenderResult<T> = Result<T, wavefunk_ui::askama::Error>;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct RenderedUi {
    html: String,
}

impl RenderedUi {
    pub fn new(html: String) -> Self {
        Self { html }
    }

    pub fn as_str(&self) -> &str {
        &self.html
    }

    pub fn as_trusted_html(&self) -> TrustedHtml<'_> {
        TrustedHtml::new(&self.html)
    }

    pub fn into_string(self) -> String {
        self.html
    }
}

impl AsRef<str> for RenderedUi {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RenderedUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.html)
    }
}

impl wavefunk_ui::askama::FastWritable for RenderedUi {
    #[inline]
    fn write_into(
        &self,
        dest: &mut dyn fmt::Write,
        _: &dyn wavefunk_ui::askama::Values,
    ) -> wavefunk_ui::askama::Result<()> {
        Ok(dest.write_str(&self.html)?)
    }
}

impl wavefunk_ui::askama::filters::HtmlSafe for RenderedUi {}

pub fn render_component<T>(component: &T) -> UiRenderResult<RenderedUi>
where
    T: Template + ?Sized,
{
    component.render().map(RenderedUi::new)
}

pub const fn trusted_html<'a>(html: &'a str) -> TrustedHtml<'a> {
    TrustedHtml::new(html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wavefunk_ui::components::{FormPanel, SplitShell};

    #[test]
    fn rendered_html_can_be_reused_as_trusted_component_slot() {
        let body = trusted_html(r#"<form action="/login"></form>"#);
        let panel = FormPanel::new("Sign in", body);
        let panel_html = render_component(&panel).expect("form panel should render");

        let shell = SplitShell::new(panel_html.as_trusted_html()).with_mode("dark");
        let shell_html = render_component(&shell).expect("split shell should render");

        assert!(shell_html.as_str().contains("wf-split-shell"));
        assert!(shell_html.as_str().contains("data-mode=\"dark\""));
        assert!(shell_html.as_str().contains("wf-form-panel"));
        assert!(
            shell_html
                .as_str()
                .contains(r#"<form action="/login"></form>"#)
        );
    }

    #[test]
    fn rendered_ui_wraps_owned_html_without_losing_access_to_string() {
        let rendered = RenderedUi::new("<section>owned</section>".to_owned());

        assert_eq!(rendered.as_str(), "<section>owned</section>");
        assert_eq!(
            rendered.as_trusted_html().as_str(),
            "<section>owned</section>"
        );
        assert_eq!(
            rendered.into_string(),
            "<section>owned</section>".to_owned()
        );
    }

    fn assert_html_safe<T: wavefunk_ui::askama::filters::HtmlSafe>() {}

    #[test]
    fn rendered_ui_can_be_embedded_as_owned_safe_html() {
        assert_html_safe::<RenderedUi>();
    }
}
