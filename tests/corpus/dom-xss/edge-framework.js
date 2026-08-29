// EDGE CASE — framework sink present (v-html) but the bound value is a static
// constant in this file. The framework rule may flag the sink pattern, but no
// untrusted source-to-sink *flow* should be claimed.
const template = `<div v-html="staticHeading"></div>`;
const staticHeading = "Account overview";
