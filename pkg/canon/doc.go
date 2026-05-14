// Package canon implements RFC 8785 JSON Canonicalization Scheme (JCS).
//
// canon.Marshal returns canonical JSON bytes that are byte-for-byte
// equivalent across compliant implementations and stable for hashing
// and signing. It is the bytes-canonicalizer used by all signing and
// verifying actors that need to agree on a single canonical form.
//
// RFC 8785 rules honored by this package:
//
//   - Object keys are sorted lexicographically by their UTF-16 code
//     unit sequence (not byte order, not Unicode code point order).
//   - Numbers are serialized per ES6 Number.prototype.toString /
//     RFC 7493: no trailing ".0", no unnecessary leading zeros,
//     scientific notation only when the magnitude requires it.
//     NaN and ±Inf are rejected.
//   - Strings use the minimal-escape form from RFC 8785 §3.2.2.2:
//     only \", \\, \b, \f, \n, \r, \t, and \u00XX for other control
//     characters. All other code points are emitted as literal UTF-8.
//   - No insignificant whitespace is emitted.
//   - Array element order is preserved.
//   - null, true, and false are emitted as lowercase literals.
//
// The package depends only on the Go standard library and adds no
// new module requires.
package canon
