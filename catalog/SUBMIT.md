# Submitting to the Hermes Plugin Catalog

`catalog/payload-guard.yaml` is the entry, ready to drop into the `plugin-catalog/` directory of
`NousResearch/hermes-agent`. It pins commit `093f00d2834620bb832d068152861b97ea4995da` (tag
`v1.1.0`) and its `capabilities:` block matches what `register()` actually installs at that
commit — the policy fails an entry whose declared capabilities and reality disagree.

## Before opening the PR

```bash
cd /path/to/hermes-agent
git checkout -B catalog/payload-guard origin/main
cp /path/to/payload-guard/catalog/payload-guard.yaml plugin-catalog/payload-guard.yaml
./venv/bin/python -c "import yaml,sys; sys.path.insert(0,'.'); \
  from hermes_cli.plugin_catalog import entry_from_mapping; \
  entry_from_mapping(yaml.safe_load(open('plugin-catalog/payload-guard.yaml')), 'entry')" \
  && echo "entry parses"
git add plugin-catalog/payload-guard.yaml
git commit -m "Add payload-guard to the plugin catalog"
git push -u origin catalog/payload-guard
gh pr create --title "Add payload-guard to the plugin catalog" --body-file catalog/PR_BODY.md
```

Admission rules this entry satisfies:

| Rule | Evidence |
| --- | --- |
| Exact 40-char SHA pin | `sha: 093f00d2…` (tag `v1.1.0`) |
| No self-updating code | the plugin makes no network calls at all; the dataset is vendored by design and refreshed only by re-running `pin_limits.py` |
| Declared capabilities match reality | hooks: `pre_api_request`, `post_api_request`, `api_request_error`; no middleware, no tools, no required env |
| Install scanner at admission | `hermes plugins validate` → **Validation passed**; `hermes plugin-guard scan` → **high=0, medium=1, PASS** (the single medium is a bounded temp-file cleanup, documented in `SECURITY.md`) |
| Owner submission | repository owner (`dacheah`) is the submitter |

## The PR body

See `catalog/PR_BODY.md` for the text to use verbatim.
