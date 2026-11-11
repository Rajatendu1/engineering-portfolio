# Engineering portfolio
Source for Rajatendu Dey's portfolio at https://rajatendu-dey.vercel.app/ . Built by Instinct, an AI assistant, under his direction.

This static site contains index.html, style.css, favicon.svg, og.png and vercel.json. The deployment configuration sets security headers and an exact hash for the inline script; update that hash if the script changes.

The projects shown are tested prototypes with stated limitations. This repository contains the portfolio website, not the standalone Actas source. The current published website is unchanged by this source backup.

GitHub Actions checks local assets, links, security headers, the inline-script CSP hash and JavaScript syntax, with negative regression cases. It does not verify remote link availability, visual layout or hosted deployments. Vercel connection and production promotion are separate steps; this CI workflow does not deploy. No license has been added.
