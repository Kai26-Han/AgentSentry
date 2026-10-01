# Chinese and English in Web

[English](#) · [中文](../web-language.md)

The login page and top-right selector offer 中文 / English. Default is Chinese; selection returns to the current page and persists in the browser even after logout.

## Scope

Navigation, breadcrumbs, titles, labels, buttons, empty-state help, approval fact cards, rule descriptions, Judge-score explanations, experiment UI and trusted threat descriptions have English translations.

Tasks/answers, tool results, documents/cards, memory text, free notes, original parameters/audit JSON, IDs, tool/rule/config names and commands remain unchanged. They are investigation data: switching display language must not change their meaning. User-authored Chinese fixtures are not automatically translated. The separate [English handbook](learning/README.md) and [English project home](../../README.md) provide documentation; Web selection does not rewrite Markdown files.

## Implementation and guarantees

[i18n.py](../../src/agentsentry/i18n.py) uses each request’s `agentsentry_language` cookie, with no shared global language. [en.json](../../src/agentsentry/locales/en.json) maps trusted UI text via `_()`/explicit `ui` filters. Translation is local lookup, with no cloud-model requests or page-data sending.

`/ui-language/zh` and `/ui-language/en` change only display preference. Redirects accept internal login/dashboard paths and preserve filters; unknown language is rejected. Login/tenant/CSRF/approval/digest/API semantics remain independent. [Language tests](../../tests/test_i18n.py) cover catalog, separate browser preferences, safe redirects, unchanged raw text, HTML escaping and English approval boundaries. Add English entries whenever trusted UI strings change.

Use your deployment’s configured `AGENTSENTRY_PORT`; language preference belongs to that browser/site and changes neither `.env` nor another service.
