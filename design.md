---
version: alpha
name: Revolut
description: Sleek dark interface. Gradient cards. Fintech precision.
colors:
  primary: "#F7F7F8"
  secondary: "#9AA0B0"
  tertiary: "#0666EB"
  neutral: "#0F1118"
  surface: "#161924"
  on-primary: "#0F1118"
typography:
  display:
    fontFamily: Inter
    fontSize: 4.75rem
    fontWeight: 700
    letterSpacing: "-0.035em"
  h1:
    fontFamily: Inter
    fontSize: 2.3rem
    fontWeight: 700
  body:
    fontFamily: Inter
    fontSize: 0.96rem
    lineHeight: 1.55
  label:
    fontFamily: Inter
    fontSize: 0.74rem
    fontWeight: 600
    letterSpacing: "0"
rounded:
  sm: 6px
  md: 10px
  lg: 16px
spacing:
  sm: 8px
  md: 16px
  lg: 32px
components:
  button-primary:
    backgroundColor: "{colors.tertiary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.md}"
    padding: 12px 20px
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary}"
    rounded: "{rounded.lg}"
    padding: 24px
---
## Overview

Revolut: sleek dark fintech interface, gradient cards, crisp data hierarchy.

## Colors

The palette is built around high-contrast neutrals and a single accent that drives interaction.

- **Primary (`#F7F7F8`):** Headlines and core text.
- **Secondary (`#9AA0B0`):** Borders, captions, and metadata.
- **Tertiary (`#0666EB`):** The sole driver for interaction. Reserve it.
- **Neutral (`#0F1118`):** The page foundation.

## Typography

- **display:** Inter 4.75rem
- **h1:** Inter 2.3rem
- **body:** Inter 0.96rem
- **label:** Inter 0.74rem

## Do's and Don'ts

- **Do** use Tertiary for exactly one action per screen.
- **Do** let Neutral carry the composition — negative space is a feature.
- **Don't** introduce gradients. This system is flat on purpose.
- **Don't** mix Tertiary with alternate accents; the single-accent rule is load-bearing.
