# Wayfinder frontend assets

Wayfinder vendors these runtime assets so the local operator app has no CDN or
frontend build requirement.

- Bootstrap 5.3.8: `bootstrap.min.css`, MIT license, https://getbootstrap.com/
- Tabulator 6.5.2: `tabulator.min.js` and `tabulator_bootstrap5.min.css`, MIT
  license, https://tabulator.info/
  - Package: https://registry.npmjs.org/tabulator-tables/-/tabulator-tables-6.5.2.tgz
  - JavaScript package path: `package/dist/js/tabulator.min.js`
  - JavaScript SHA-256: `04802e757fa4189342c666d0f970a01d761c312798f31ffc664c24cbccc7ce3e`
  - JavaScript SRI: `sha256-BIAudX+kGJNCxmbQ+XCgHXYcMSeY8x/8Zkwky8zHzj4=`
  - CSS SHA-256: `46f2e6afd39e51167b1c850b20f7f1da608495e5ec293ce0826fca4e6a36cace`
- Wayfinder logo SHA-256: `622b73540f8e85bbeb14281cba4cd54880db9f05b3f188fb8359cff84b7c6f2a`

Keep the adjacent license files when updating either asset. Review upstream
release notes and rerun the Wayfinder browser suite before changing versions.
