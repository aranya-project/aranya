# Aranya C API Docs

Aranya client API docs are hosted on this site.
Currently, that's only Doxygen C API docs.

Each release of Aranya will have its own documentation website in a different subdirectory:
- [v0.4.0](capi/v0.4.0/)
- [v0.3.0](capi/v0.3.0/)

## Deploying Docs For New Releases

When a new version of Aranya is released, the docs are automatically pushed to a subfolder corresponding to the release tag on the `gh-pages` branch.

This is done by the `publish.yml` workflow on the `main` branch of this repo.

## Deploying the site
Deploying is easy, just merge a PR to the `gh-pages` branch. The documentation repo is configured to use Github's built-in branch push actions to trigger builds and deploy to GH pages. The target branch and directory can be configured in the GH Pages settings section of the repo, if you need to test a deployment. Just note however, we don't have a proper staging environment, so these deployments will go live to the production github.io site.

## Develop Locally
We currently deploy directly to GitHub Pages, so there isn't a staging site to preview any changes. The best way to test documentation is to deploy a local server using `Jekyll`. Follow the [install instructions](https://jekyllrb.com/docs/installation/) to install Jekyll on your system, and then simply run `jekyll serve -w` which will launch a web server on your machine.
