---
name: demo-components
description: Discover, select, connect, and deploy pre-configured F5 sales-demo infrastructure components from the live demo-resources catalog. Use when users build a demo, need origin or traffic infrastructure, compare available components, design a multi-component demo environment, or request Terraform deployment guidance.
---

# Demo Components

Use live documentation and advance only as far as the user's request requires. Reuse content already
fetched during the session.

## Discover components

1. Fetch `https://f5-sales-demo.github.io/demo-resources/llms.txt` with an available HTTP or fetch
   tool.
2. Read the component entries and their descriptions. Treat the returned catalog as authoritative.
3. Present only components that appear in the catalog. Recommend the smallest combination that meets
   the demo goal and link to the relevant catalog entries.
4. Ask the user to select a component when their requirements do not determine one.

Common combinations include:

- WAF, API security, or bot defense: an origin server plus a traffic generator.
- CDN behavior: an origin server plus a CDN simulator.
- Client-side defense: an origin server, with a traffic generator only when the scenario needs it.

## Inspect a component

After validating the component slug against the live catalog, fetch its profile from:

`https://f5-sales-demo.github.io/demo-resources/_llms-txt/en/{component}.txt`

Summarize its purpose, architecture, installed software, inputs, outputs, integration points, and
compatible components. Do not infer capabilities missing from the live profile.

## Prepare a deployment

When the user wants deployment details, fetch:

`https://f5-sales-demo.github.io/{component}/_llms-txt/en/03-deploy.txt`

Then:

1. Confirm the target is an authorized demo or lab environment.
2. Follow the live guide for prerequisites, Terraform variables, commands, and outputs; do not rely on
   a remembered variable list.
3. Collect required non-secret values. Never request, print, commit, or place credentials in chat.
   Keep local variable and state files out of version control.
4. Run or guide `terraform init` and `terraform plan` before any apply. Explain the planned resources,
   cost-sensitive choices, and destructive changes.
5. Obtain explicit user confirmation after the plan is available and before running
   `terraform apply`. A general request for deployment is not approval of an unseen plan.
6. After apply, report verified outputs and health checks. Include teardown guidance when the user no
   longer needs the environment.

For multi-component environments, show connections and deployment order. Deploy dependencies such as
the origin first, then pass only documented outputs into downstream component inputs.

## Guardrails

- Stop on HTTP errors or missing catalog entries; do not fabricate a component, URL, variable, or
  capability.
- Do not use the general portal or individual component `llms.txt` files as substitutes for the three
  endpoints above.
- Keep discovery read-only until the user requests repository changes or deployment actions.
- Never apply Terraform to an unauthorized, third-party, or production environment.
