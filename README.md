# Traffic Generator

🌐 English |
[日本語](https://f5-sales-demo.github.io/traffic-generator/ja/) |
[한국어](https://f5-sales-demo.github.io/traffic-generator/ko/) |
[简体中文](https://f5-sales-demo.github.io/traffic-generator/zh-cn/) |
[繁體中文](https://f5-sales-demo.github.io/traffic-generator/zh-tw/) |
[Español](https://f5-sales-demo.github.io/traffic-generator/es/) |
[Português](https://f5-sales-demo.github.io/traffic-generator/pt-br/) |
[Français](https://f5-sales-demo.github.io/traffic-generator/fr/) |
[Deutsch](https://f5-sales-demo.github.io/traffic-generator/de/) |
[Italiano](https://f5-sales-demo.github.io/traffic-generator/it/) |
[العربية](https://f5-sales-demo.github.io/traffic-generator/ar/) |
[हिन्दी](https://f5-sales-demo.github.io/traffic-generator/hi/) |
[ไทย](https://f5-sales-demo.github.io/traffic-generator/th/)

[![GitHub Pages Deploy](https://github.com/f5-sales-demo/traffic-generator/actions/workflows/github-pages-deploy.yml/badge.svg)](https://github.com/f5-sales-demo/traffic-generator/actions/workflows/github-pages-deploy.yml)
[![Repository Settings](https://github.com/f5-sales-demo/traffic-generator/actions/workflows/enforce-repo-settings.yml/badge.svg)](https://github.com/f5-sales-demo/traffic-generator/actions/workflows/enforce-repo-settings.yml)
[![License](https://img.shields.io/github/license/f5-sales-demo/traffic-generator)](LICENSE)

Deploy the Traffic Generator on Azure or AWS to run security-testing suites against F5 Distributed Cloud demo environments. Each cloud has an independent Terraform root and state; choose one deployment path and do not mix their commands or state.

## Deployment choices

- **Azure:** existing deployment in [`terraform/`](terraform/)
- **AWS:** public-subnet worker with an Elastic IP attached directly to its primary network interface, jumpbox-restricted SSH, Systems Manager recovery, deny-all default security group, encrypted VPC Flow Logs, S3 EventBridge notifications, server access logging, and a cross-region evidence replica in [`terraform/aws/`](terraform/aws/)

Full documentation is available at **[https://f5-sales-demo.github.io/traffic-generator/](https://f5-sales-demo.github.io/traffic-generator/)**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow rules,
branch naming, and CI requirements.

## License

See [LICENSE](LICENSE).
