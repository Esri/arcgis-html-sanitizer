import { Sanitizer } from './index';

// This file contains basic tests that validate the the utility methods.
// For XSS attack sanitizer testing see xss.test.ts

describe('Sanitizer', () => {
  test('creates the Sanitizer object and extends options appropriately', () => {
    // Test with no arguments
    const sanitizer1 = new Sanitizer();
    const defaultSanitizer1 = new Sanitizer();
    const defaultOptions1 = Object.create(
      defaultSanitizer1.arcgisFilterOptions
    );
    defaultOptions1.whiteList = defaultSanitizer1.arcgisWhiteList;
    expect(sanitizer1.xssFilterOptions).toEqual(defaultOptions1);

    // Extending the defaults
    const sanitizer2 = new Sanitizer(
      { allowCommentTag: false, whiteList: { blockquote: [] } },
      true
    );
    const defaultSanitizer2 = new Sanitizer();
    const filterOptions2 = Object.create(defaultSanitizer2.arcgisFilterOptions);
    filterOptions2.whiteList = defaultSanitizer2.arcgisWhiteList;
    filterOptions2.whiteList.blockquote = [];
    filterOptions2.allowCommentTag = false;
    expect(sanitizer2.xssFilterOptions).toEqual(filterOptions2);

    // Passing an empty whitelist
    const sanitizer3 = new Sanitizer({ whiteList: null }, true);
    const defaultSanitizer3 = new Sanitizer();
    const defaultOptions3 = Object.create(
      defaultSanitizer3.arcgisFilterOptions
    );
    defaultOptions3.whiteList = defaultSanitizer3.arcgisWhiteList;
    expect(sanitizer3.xssFilterOptions).toEqual(defaultOptions3);

    // Test overriding defaults
    const sanitizer4 = new Sanitizer({ whiteList: { a: [] } });
    expect(sanitizer4.xssFilterOptions).toEqual({ whiteList: { a: [] } });
  });

  test('sanitizes a value', () => {
    const sanitizer = new Sanitizer();

    // Numbers
    expect(sanitizer.sanitize(NaN)).toBe(null);
    expect(sanitizer.sanitize(Infinity)).toBe(null);
    expect(sanitizer.sanitize(123)).toBe(123);
    expect(sanitizer.sanitize(123)).toBe(123);

    // Boolean
    expect(sanitizer.sanitize(true)).toBe(true);
    expect(sanitizer.sanitize(false)).toBe(false);

    // Strings
    const basicString = 'Hello World';
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';
    const sanitizedInvalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" />';

    expect(sanitizer.sanitize(basicString)).toBe(basicString);
    expect(sanitizer.sanitize(validHtml)).toBe(validHtml);
    expect(sanitizer.sanitize(invalidHtml)).toBe(sanitizedInvalidHtml);

    // Built in Objects:https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects
    // Value Properties (Infinity and NanN defined in Numbers above)
    expect(sanitizer.sanitize(undefined)).toBe(null);
    expect(sanitizer.sanitize(null)).toBe(null);

    // Fundamental objects
    expect(sanitizer.sanitize(Object)).toBe(null);
    expect(sanitizer.sanitize(Function)).toBe(null);
    expect(sanitizer.sanitize(Boolean)).toBe(null);
    expect(sanitizer.sanitize(Symbol)).toBe(null);
    expect(sanitizer.sanitize(Error)).toBe(null);
    expect(sanitizer.sanitize(EvalError)).toBe(null);
    expect(sanitizer.sanitize(RangeError)).toBe(null);
    expect(sanitizer.sanitize(ReferenceError)).toBe(null);
    expect(sanitizer.sanitize(SyntaxError)).toBe(null);
    expect(sanitizer.sanitize(TypeError)).toBe(null);
    expect(sanitizer.sanitize(URIError)).toBe(null);

    // Number and dates
    expect(sanitizer.sanitize(Number)).toBe(null);
    expect(sanitizer.sanitize(Math)).toBe(null);
    expect(sanitizer.sanitize(Date)).toBe(null);
    expect(sanitizer.sanitize(new Date())).toBe(null);

    // Text processing
    expect(sanitizer.sanitize(String)).toBe(null);
    expect(sanitizer.sanitize(RegExp)).toBe(null);
    expect(sanitizer.sanitize(/\w+/)).toBe(null);

    // Indexed collections
    expect(sanitizer.sanitize(Array)).toBe(null);
    expect(sanitizer.sanitize(Int8Array)).toBe(null);
    expect(sanitizer.sanitize(Uint8Array)).toBe(null);
    expect(sanitizer.sanitize(Uint8ClampedArray)).toBe(null);
    expect(sanitizer.sanitize(Int16Array)).toBe(null);
    expect(sanitizer.sanitize(Uint16Array)).toBe(null);
    expect(sanitizer.sanitize(Int32Array)).toBe(null);
    expect(sanitizer.sanitize(Uint32Array)).toBe(null);
    expect(sanitizer.sanitize(Float32Array)).toBe(null);
    expect(sanitizer.sanitize(Float64Array)).toBe(null);

    // Keyed collections
    expect(sanitizer.sanitize(Map)).toBe(null);
    expect(sanitizer.sanitize(Set)).toBe(null);
    expect(sanitizer.sanitize(WeakMap)).toBe(null);
    expect(sanitizer.sanitize(WeakSet)).toBe(null);

    // Structured Data
    expect(sanitizer.sanitize(ArrayBuffer)).toBe(null);
    expect(sanitizer.sanitize(DataView)).toBe(null);
    expect(sanitizer.sanitize(JSON)).toBe(null);

    // Control abstraction objects
    expect(sanitizer.sanitize(Promise)).toBe(null);

    // Reflection
    expect(sanitizer.sanitize(Reflect)).toEqual({});
    expect(sanitizer.sanitize(Proxy)).toBe(null);

    // Internationalization
    expect(sanitizer.sanitize(Intl)).toEqual({});
    expect(sanitizer.sanitize(Intl.Collator)).toBe(null);
    expect(sanitizer.sanitize(Intl.DateTimeFormat)).toBe(null);
    expect(sanitizer.sanitize(Intl.NumberFormat)).toBe(null);

    // Others
    expect(sanitizer.sanitize(arguments)).toBe(null);
    expect(sanitizer.sanitize(() => 'test')).toBe(null);
    expect(sanitizer.sanitize(new Error('test'))).toBe(null);
  });

  test('deeply sanitizes an object', () => {
    const sanitizer = new Sanitizer();

    // If object is clean, it return the exact same object;
    const cleanObj1 = {
      a: null,
      b: true,
      c: 'clean string'
    };
    const result1 = sanitizer.sanitize(cleanObj1);
    expect(result1).toBe(cleanObj1);

    // Sanitizes dirty object
    const result2 = sanitizer.sanitize({
      a: 1,
      b: true,
      c: 'clean string',
      d: 'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />',
      e: [
        1,
        true,
        'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />',
        ['inner', 'array']
      ],
      f: new Date()
    });
    const expected2 = {
      a: 1,
      b: true,
      c: 'clean string',
      d: 'Evil <img src="https://exmaple.org/myImg.jpg" />',
      e: [
        1,
        true,
        'Evil <img src="https://exmaple.org/myImg.jpg" />',
        ['inner', 'array']
      ],
      f: null
    };
    expect(result2).toEqual(expected2);
  });

  test('checks if string is valid html', () => {
    const basicString = 'Hello World';
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';

    const sanitizer = new Sanitizer();

    expect(sanitizer.validate(basicString).isValid).toBe(true);
    expect(sanitizer.validate(validHtml).isValid).toBe(true);
    expect(sanitizer.validate(invalidHtml).isValid).toBe(false);
  });

  test('extends an object of array by concatenating arrays', () => {
    // tslint:disable-next-line:no-string-literal
    const _extendObjectOfArrays = new Sanitizer()['_extendObjectOfArrays'];

    const result = _extendObjectOfArrays([
      { a: [1, 2] },
      { a: [3, 4], b: [1, 2] },
      { b: [3, 4] }
    ]);

    expect(result).toEqual({ a: [1, 2, 3, 4], b: [1, 2, 3, 4] });
  });

  test('returns null of iteration fails', () => {
    // tslint:disable-next-line:no-string-literal
    const _iterateOverObject = new Sanitizer()['_iterateOverObject'];

    // Will fail because "this" is not defined
    expect(_iterateOverObject({ a: 1 })).toBe(null);
  });
});
