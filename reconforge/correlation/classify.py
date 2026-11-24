"""Derived classifications applied centrally by the correlation engine.

* URL functional categories (never implies a route is vulnerable)
* query parameter inventory
* third-party service categories
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

URL_CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("authentication", re.compile(r"/(log[-_]?in|sign[-_]?in|signin|auth|oauth2?|sso|saml|openid|login\.php|session|logout|mfa|2fa|otp|callback)(/|$|\.|\?)", re.I)),
    ("account_management", re.compile(r"/(register|sign[-_]?up|account|profile|settings|password|forgot|reset|recover|verify|activation|me)(/|$|\.|\?|-)", re.I)),
    ("administrative", re.compile(r"/(admin|administrator|wp-admin|manage|management|console|dashboard|cpanel|backend|internal|staff|moderator)(/|$|\.|\?)", re.I)),
    ("graphql", re.compile(r"graphql|/gql(/|$)", re.I)),
    ("public_api", re.compile(r"/(api|rest|v\d+|rpc|services?|ws)(/|$)|\.json($|\?)", re.I)),
    ("documentation", re.compile(r"/(docs?|documentation|swagger|openapi|api-docs|redoc|help|guide|manual)(/|$|\.|-)|\.(md|pdf)($|\?)", re.I)),
    ("upload", re.compile(r"/(upload|uploads|import|attach|attachment)(/|$|s/|\.|\?)", re.I)),
    ("file_handling", re.compile(r"/(download|file|files|export|media|document|documents|attachment|getfile|fetch)(/|$|\.|\?)|\.(zip|tar|gz|csv|xlsx?|docx?|pptx?)($|\?)", re.I)),
    ("search", re.compile(r"/(search|find|query|lookup|autocomplete|suggest)(/|$|\.|\?)|[?&](q|query|search|s|keyword)=", re.I)),
    ("dev_staging", re.compile(r"(^|[./-])(dev|develop|staging|stage|stg|test|qa|uat|sandbox|debug|phpinfo|preprod)([./-]|$)", re.I)),
    ("static", re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|mp4|webm)($|\?)", re.I)),
]


def url_categories(url: str) -> list[str]:
    parts = urlsplit(url)
    host_path = (parts.hostname or "").split(".")[0] + parts.path + ("?" + parts.query if parts.query else "")
    cats = []
    for name, rx in URL_CATEGORIES:
        target = host_path if name == "dev_staging" else parts.path + ("?" + parts.query if parts.query else "")
        if rx.search(target):
            cats.append(name)
    if url.startswith(("ws://", "wss://")):
        cats.append("public_api")
    return sorted(set(cats)) or ["other"]


def query_params(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


THIRD_PARTY = [
    # (suffix, category, service)
    ("googletagmanager.com", "analytics", "Google Tag Manager"), ("google-analytics.com", "analytics", "Google Analytics"),
    ("segment.com", "analytics", "Segment"), ("segment.io", "analytics", "Segment"), ("hotjar.com", "analytics", "Hotjar"),
    ("mixpanel.com", "analytics", "Mixpanel"), ("amplitude.com", "analytics", "Amplitude"), ("heap.io", "analytics", "Heap"),
    ("stripe.com", "payments", "Stripe"), ("paypal.com", "payments", "PayPal"), ("braintreegateway.com", "payments", "Braintree"),
    ("adyen.com", "payments", "Adyen"), ("squareup.com", "payments", "Square"),
    ("zendesk.com", "customer_support", "Zendesk"), ("intercom.io", "customer_support", "Intercom"),
    ("intercomcdn.com", "customer_support", "Intercom"), ("freshdesk.com", "customer_support", "Freshdesk"),
    ("drift.com", "customer_support", "Drift"), ("livechatinc.com", "customer_support", "LiveChat"),
    ("sentry.io", "error_tracking", "Sentry"), ("sentry-cdn.com", "error_tracking", "Sentry"), ("bugsnag.com", "error_tracking", "Bugsnag"),
    ("rollbar.com", "error_tracking", "Rollbar"), ("newrelic.com", "monitoring", "New Relic"), ("nr-data.net", "monitoring", "New Relic"),
    ("datadoghq.com", "monitoring", "Datadog"), ("statuspage.io", "monitoring", "Atlassian Statuspage"),
    ("hubspot.com", "marketing_automation", "HubSpot"), ("hs-scripts.com", "marketing_automation", "HubSpot"),
    ("marketo.net", "marketing_automation", "Marketo"), ("pardot.com", "marketing_automation", "Pardot"),
    ("mailchimp.com", "marketing_automation", "Mailchimp"), ("list-manage.com", "marketing_automation", "Mailchimp"),
    ("sendgrid.net", "email_delivery", "SendGrid"), ("mailgun.org", "email_delivery", "Mailgun"), ("_spf.google.com", "email_delivery", "Google Workspace"),
    ("amazonses.com", "email_delivery", "Amazon SES"), ("mandrillapp.com", "email_delivery", "Mandrill"), ("sparkpostmail.com", "email_delivery", "SparkPost"),
    ("outlook.com", "email_delivery", "Microsoft 365"), ("protection.outlook.com", "email_delivery", "Microsoft 365"),
    ("okta.com", "identity", "Okta"), ("oktacdn.com", "identity", "Okta"), ("auth0.com", "identity", "Auth0"),
    ("login.microsoftonline.com", "identity", "Microsoft Entra ID"), ("accounts.google.com", "identity", "Google Identity"),
    ("amazoncognito.com", "identity", "Amazon Cognito"), ("onelogin.com", "identity", "OneLogin"), ("pingidentity.com", "identity", "Ping Identity"),
    ("duosecurity.com", "identity", "Duo"),
    ("cloudfront.net", "cdn", "Amazon CloudFront"), ("akamaized.net", "cdn", "Akamai"), ("akamaiedge.net", "cdn", "Akamai"),
    ("fastly.net", "cdn", "Fastly"), ("cloudflare.com", "cdn", "Cloudflare"), ("cdnjs.cloudflare.com", "cdn", "cdnjs"),
    ("jsdelivr.net", "cdn", "jsDelivr"), ("unpkg.com", "cdn", "unpkg"), ("bootstrapcdn.com", "cdn", "BootstrapCDN"),
    ("gstatic.com", "cdn", "Google static"), ("fonts.googleapis.com", "cdn", "Google Fonts"), ("edgekey.net", "cdn", "Akamai"),
    ("amazonaws.com", "cloud_hosting", "Amazon Web Services"), ("azurewebsites.net", "cloud_hosting", "Azure App Service"),
    ("cloudapp.azure.com", "cloud_hosting", "Azure"), ("herokuapp.com", "cloud_hosting", "Heroku"), ("herokudns.com", "cloud_hosting", "Heroku"),
    ("appspot.com", "cloud_hosting", "Google App Engine"), ("vercel.app", "cloud_hosting", "Vercel"), ("netlify.app", "cloud_hosting", "Netlify"),
    ("github.io", "cloud_hosting", "GitHub Pages"), ("pages.dev", "cloud_hosting", "Cloudflare Pages"), ("firebaseapp.com", "cloud_hosting", "Firebase"),
    ("googleapis.com", "external_api", "Google APIs"), ("twilio.com", "external_api", "Twilio"), ("mapbox.com", "external_api", "Mapbox"),
    ("recaptcha.net", "security", "reCAPTCHA"), ("hcaptcha.com", "security", "hCaptcha"),
    ("facebook.net", "social", "Meta"), ("twitter.com", "social", "X / Twitter"), ("linkedin.com", "social", "LinkedIn"),
    ("youtube.com", "media", "YouTube"), ("vimeo.com", "media", "Vimeo"), ("github.com", "code_hosting", "GitHub"),
]


def classify_third_party(host: str) -> tuple[str, str | None]:
    h = host.lower()
    best = None
    for suffix, cat, svc in THIRD_PARTY:
        if h == suffix or h.endswith("." + suffix) or (suffix.startswith("_") and suffix in h):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, cat, svc)
    return (best[1], best[2]) if best else ("external", None)
