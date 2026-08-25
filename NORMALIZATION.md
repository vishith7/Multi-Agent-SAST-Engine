# Normalization in Taintlace

Taintlace relies on multiple layers of **normalization** (canonicalization and cleaning) to ensure that code structures, dataflow paths, and text representations remain consistent. 

Normalization is crucial for:
1. **Accurate Deduplication**: Preventing the system from reporting the same vulnerability multiple times due to minor code formatting, variable names, or commutative statement ordering differences.
2. **Context Compression**: Enhancing BPE tokenizer compression efficiency by matching identical phrases and structures, which avoids redundant vocabulary entries.
3. **Consistent LLM Prompting**: Providing clean, standardized inputs to the LLM Cascade to maximize verification accuracy and eliminate parsing errors.

---

## 1. Commutative Operation Normalization (Semantic Canonicalization)

### Purpose
In programming, many binary operators are **commutative**—meaning the order of operands does not change the semantic meaning of the expression. For example:
* `x == y` is semantically identical to `y == x`.
* `a + b` is semantically identical to `b + a`.

Without canonicalization, two identical dataflow paths containing these variations would produce different SHA-256 fingerprints, resulting in duplicate findings. Commutative normalization resolves this by ordering operands deterministically.

### Implementation
Implemented in [`sast-engine/orchestrator/dedupe_anonymize.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dedupe_anonymize.py#L7-L27) using the `canonicalize_ops` function:

```python
def tokenize_balanced(text):
    # Lexes text into space, string, operator, word, and balanced bracketed tokens
    ...

def canonicalize_ops(text):
    try:
        tokens = tokenize_balanced(text)
    except Exception:
        return text

    # Commutative operators: handles JS ===, !== and logical &&, || in Java/JS/PHP
    comm_ops = {'+', '*', '==', '!=', '===', '!==', '&&', '||', '&', '|', '^'}
    op_indices = [idx for idx, t in enumerate(tokens) if t[0] == 'operator' and t[1] in comm_ops]
    
    if not op_indices:
        return text
        
    # Process from right to left to keep indexes stable
    for op_idx in reversed(op_indices):
        ...
        # Swaps operands around the operator if left_str > right_str
        if left_str > right_str:
            tokens[left_start:right_end] = swapped_tokens
            
    return "".join(t[1] for t in tokens)
```

### Trace Example: `req.input == user_id` vs `user_id == req.input`

Consider two code snippets from different branches:
* **Snippet A**: `if (req.input == user_id)`
* **Snippet B**: `if (user_id == req.input)`

Let's trace how the canonicalization and anonymization pipeline normalizes them:

#### Step 1: Commutative Check
* **Snippet A (`req.input == user_id`)**:
  * Regex matches operand `req.input` (actually matches `input` and `user_id` surrounding `==`, since `.` acts as a boundary).
  * Left operand = `input`
  * Operator = `==`
  * Right operand = `user_id`
  * Lexicographical check: Is `"input" > "user_id"`? No. String remains `req.input == user_id`.
* **Snippet B (`user_id == req.input`)**:
  * Left operand = `user_id`
  * Operator = `==`
  * Right operand = `input`
  * Lexicographical check: Is `"user_id" > "input"`? **Yes**.
  * The helper function swaps the operands and rewrites the string as: `req.input == user_id`.

#### Step 2: Anonymization Pipeline
Once both snippets are normalized to `req.input == user_id`, the anonymizer ([`dedupe_anonymize.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dedupe_anonymize.py)) maps identifiers to placeholders (whitelisting configuration keywords):
* Assuming `req` and `input` are in the configuration whitelist:
  * `req` $\rightarrow$ `req`
  * `input` $\rightarrow$ `input`
  * `user_id` $\rightarrow$ `<VAR_1>`
* **Final Output for BOTH snippets**: `req.input == <VAR_1>`

Both snippets now have the exact same string structure, resulting in a single collapsed finding instead of two duplicate entries.

---

## 2. Unicode and Whitespace Normalization (Textual Cleaning)

### Purpose
Code bases often contain formatting quirks: extra spaces, tabs, mixed line-endings (`\r\n` vs `\n`), or non-breaking spaces (`\xa0`). Additionally, source code files might contain Unicode characters formatted differently in byte streams (e.g. decomposed vs composed accent characters).

Textual cleaning guarantees that:
* Trivial formatting changes do not alter tokenizer pattern-matching.
* Context prompts sent to the LLM are clean, legible, and token-efficient.

### Implementation
Implemented in [`sast-engine/llm/tokenizer.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/llm/tokenizer.py#L112-L184) under `extract_and_normalize`:

```python
def clean(t):
    if not t:
        return ""
    # 1. Normalize Unicode characters to Normalization Form Canonical Composition (NFC)
    t = unicodedata.normalize('NFC', str(t))
    # 2. Collapse any sequence of whitespaces, tabs, or non-breaking spaces (\xa0) into a single space
    t = re.sub(r'[\s\xa0]+', ' ', t)
    return t.strip()
```

### Trace Example: Unicode Composition & Whitespace Collapsing

Suppose a finding contains the following raw metadata and code node string:
* **Raw Code**: `  user_name   =	  "café" ` (contains multiple spaces, a tab character, and the decomposed form of `é`: `e` (`U+0065`) + acute accent `◌́` (`U+0301`))

Let's trace how `clean` processes this string:

1. **`unicodedata.normalize('NFC', str(t))`**:
   * Inspects the decomposed characters `e` (`U+0065`) and `◌́` (`U+0301`).
   * Composes them into the single equivalent Unicode character `é` (`U+00E9`).
   * The string becomes: `  user_name   =	  "café" ` (with `é` as a single code-point).
2. **`re.sub(r'[\s\xa0]+', ' ', t)`**:
   * Matches the leading space sequence `  ` $\rightarrow$ replaced by ` `
   * Matches the space-tab-space sequence `   =\t  ` $\rightarrow$ replaced by ` = `
   * Matches the trailing space ` ` $\rightarrow$ replaced by ` `
   * The string becomes: ` user_name = "café" `
3. **`t.strip()`**:
   * Removes the leading and trailing spaces.
   * **Final Output**: `user_name = "café"`

This clean string is now ready for BPE Tokenization or LLM prompting.

---

## 3. Dynamic BPE Pattern Normalization

### Purpose
The **BPE With Learning Tokenizer** ([`sast-engine/llm/tokenizer.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/llm/tokenizer.py)) builds a dictionary of recurring code patterns. If patterns are not cleaned, a pattern like `db.execute(query)` and `db.execute(  query  )` would be tracked separately, failing to reach the frequency threshold ($\geq 10$ occurrences) required to promote them.

### Implementation
1. Before extracting candidate patterns, the tokenizer converts the entire finding object into a single cleaned string using the `extract_and_normalize` function described above.
2. The tokenizer splits the text into lines and extracts sub-phrases (n-grams) from these cleaned lines.
3. This guarantees that frequency counts are tracked against a standardized, normalized text structure, leading to higher compression ratios.

---

## Summary of Normalization Flow

```
Raw Finding Code Path
  │
  ├──► [Whitespace Cleaning] ──► Collapses multiple spaces, tabs, and \xa0 to single space
  │
  ├──► [Unicode Normalization] ──► Converts Unicode string characters to NFC format
  │
  ├──► [Commutative Operations] ──► Reorders binary commutative operands alphabetically (e.g. b + a -> a + b)
  │
  ├──► [Anonymization Map] ──► Maps local variables/attributes sequentially (<VAR_1>, <FUNC_1>)
  │
  └──► Final Structural Fingerprint & Context Hash
```
