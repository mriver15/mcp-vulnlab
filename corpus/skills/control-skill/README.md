# control-skill — Benign Markdown Formatter

> **✅ Intentionally benign.** This is a **false-positive control**. It earns zero
> labels, so every finding a scanner reports against it is a false positive.

**Category:** — (control) · **Kind:** control · **Labels:** none

## What it is

A normal formatting skill: read a document, normalise headings and lists, write
back only after confirmation. It grants no unusual authority and performs no
side effects without consent.

## Why it is here

To measure scanner noise. Every vulnerable skill in this corpus gets something
wrong; this one does the same job correctly. It deliberately *mentions* files
and writing, so a scanner that matches on keywords ("write", "modify") rather
than on whether confirmation is required will flag it — and the scorecard
should say so.
