# Interactive Negligibility Explainer — Design

## Goal

Create one self-contained offline HTML page that explains why the P0-A privacy bound uses `1/n` as the random-guessing baseline while only the adversary's additional advantage is negligible in the security parameter `lambda`.

The final artifact will be saved as `negligibility_explainer.html` in the repository root. It will not modify the paper or P0-A implementation.

## Chosen direction

Use a guided single-page story:

1. Connect the probability statement to the P0-A query path.
2. Let the reader manipulate `n`, `lambda`, and the growth rule for `n(lambda)`.
3. Plot `1/n(lambda)` against inverse-polynomial test functions.
4. End with the formally valid paper statement.

This structure favors teaching flow while keeping every control and conclusion on one scrollable page.

## Content and interactions

### 1. P0-A query anatomy

Show the path

`D -> target i -> record selector hat(v_i) -> window selector v_i -> m_q -> ct_q -> Eval(ct_q, m_DB) -> d_i`.

An interactive database row will let the reader:

- change database size `n`;
- click a target record `i`;
- see the corresponding record-level one-hot selector;
- see the selected logical-slot window `J_i`;
- observe that a blind record-index guess succeeds with probability `1/n`.

The diagram will distinguish logical selector entries and encoded plaintexts. It will not imply that logical slots are polynomial coefficients.

### 2. Asymptotic laboratory

Controls:

- security parameter `lambda`;
- one of three growth rules: fixed `n`, `n(lambda) = lambda^k`, or `n(lambda) = 2^lambda`;
- exponent `k` for the polynomial case;
- test-polynomial degree `r`, representing the threshold `1/lambda^r`.

The page will calculate and graph `f(lambda) = 1/n(lambda)` on a logarithmic scale. Each mode will explain its formal status:

- fixed `n`: `1/n` is constant as `lambda` grows, so it is not negligible;
- `n(lambda) = lambda^k`: `1/n = 1/lambda^k`; choosing the polynomial `p(lambda) = lambda^(k+1)` witnesses that it is not negligible;
- `n(lambda) = 2^lambda`: `1/n = 2^(-lambda)`, which eventually falls below every inverse polynomial and is negligible.

Large values will be handled in logarithmic form to avoid numeric overflow.

### 3. Baseline and advantage

Visually decompose

`Pr[successful guess] <= 1/n + negl(lambda)`

into:

- `1/n`: unavoidable random-guessing baseline over `n` records;
- `negl(lambda)`: maximum additional advantage attributable to the adversary's view.

A small guessing demonstration will highlight one uniformly selected record and compare a blind guess with the selected index. It illustrates the baseline only; it will not be presented as cryptographic evidence.

### 4. Paper-safe conclusion

End with two contrasting statements:

- invalid under the paper's current definitions: `1/n is negligible in lambda`;
- valid: `1/n is the random-guessing probability, and the adversary's additional advantage is negligible in lambda`.

Also state the reason: the paper defines `n` as database size independently of `lambda`; therefore no asymptotic growth sufficient to make `1/n` negligible has been established.

## Presentation

- Single HTML file with embedded CSS and JavaScript.
- No CDN, external font, image, script, stylesheet, or network request.
- Native HTML and SVG for formulas, diagrams, and plots.
- Responsive desktop/mobile layout.
- Keyboard-operable controls, visible focus, sufficient contrast, and explanatory text accompanying color.
- Compact academic visual style aligned with the paper rather than a product dashboard.

## Boundaries

- Explain existing P0-A notation and privacy interpretation only.
- Do not redesign P0-A, alter its code, or change the manuscript.
- Do not claim that practical database size is normally a function of the security parameter.
- Do not conflate random-guess success with adversarial advantage.
- Do not claim a finite graph proves the universal asymptotic definition; the graph is intuition, while the accompanying argument supplies the formal conclusion.

## Verification

- Open the file directly from disk and exercise every control.
- Confirm all three growth models produce the correct formulas and verdicts.
- Check fixed, polynomial, and exponential examples at several `lambda` values.
- Confirm no external URLs or resource dependencies exist.
- Check desktop and narrow viewport rendering.
- Confirm the displayed P0-A notation matches the paper: `hat(v_i)`, `v_i`, `m_q`, `ct_q`, `m_DB`, `J_i`, and `d_i`.
