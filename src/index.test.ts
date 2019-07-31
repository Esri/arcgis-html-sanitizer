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
    // @ts-ignore
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
    // @ts-ignore
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

  test('check for allowed protocols', () => {
    const disallowedProtocols: string[] = ['ftp', 'smb'];
    const allowedProtocols: string[] = [
      'http',
      'https',
      'mailto',
      'iform',
      'tel',
      'flow',
      'lfmobile',
      'arcgis-navigator',
      'arcgis-appstudio-player',
      'arcgis-survey123',
      'arcgis-collector',
      'arcgis-workforce',
      'arcgis-explorer',
      'arcgis-trek2there',
      'mspbi',
      'comgooglemaps',
      'pdfefile',
      'pdfehttp',
      'pdfehttps',
      'boxapp',
      'boxemm',
      'awb',
      'awbs',
      'gropen',
      'radarscope'
    ];
    const rootAnchor = '<a href="/">Link</a>';
    const hashAnchor = '<a href="#">Link</a>';
    const hashIdAnchor = '<a href="#test">Link</a>';

    const sanitizer = new Sanitizer();

    // Ensure the allowed protocols are not stripped out
    allowedProtocols.forEach(protocol => {
      const anchor = `<a href="${protocol}://someurl.tld?param1=1&param2=2">Link</a>`;
      expect(sanitizer.sanitize(anchor)).toBe(anchor);
    });
    // Ensure disallowed protocols are still disallowed and are sanitized
    disallowedProtocols.forEach(protocol => {
      const anchor = `<a href="${protocol}://someurl.tld?param1=1&param2=2">Link</a>`;
      expect(sanitizer.sanitize(anchor)).toBe('<a href>Link</a>');
    });

    // Check for caps and mixed case protocols
    const capsHttps = `<a href="HTTPS://someurl.tld?param1=1">Link</a>`;
    const capsTel = `<a href="tel:+1-111-111-1111">Tel</a>`;
    const mixedHttp = `<a href="hTTp://someurl.tld?param1=1">Link</a>`;
    expect(sanitizer.sanitize(capsHttps)).toBe(capsHttps);
    expect(sanitizer.sanitize(capsTel)).toBe(capsTel);
    expect(sanitizer.sanitize(mixedHttp)).toBe(mixedHttp);

    // Ensure we can still use "/" and "#" as anchor href values
    expect(sanitizer.sanitize(rootAnchor)).toBe(rootAnchor);
    expect(sanitizer.sanitize(hashAnchor)).toBe(hashAnchor);
    expect(sanitizer.sanitize(hashIdAnchor)).toBe(hashIdAnchor);
  });

  test('check for some of the allowed tags and attributes', () => {
    const u = '<u>String</u>';
    const hr = '<hr>';
    const ol = '<ol><li>List Item 1</li><li>List Item 2</li></ol>';
    const safeDiv = '<div style="display:none;">Text content</div>';
    const unsafeDiv = '<div onerror="alert(1)">Text content</div>';
    const strippedDiv = '<div>Text content</div>';

    const sanitizer = new Sanitizer();

    expect(sanitizer.sanitize(u)).toBe(u);
    expect(sanitizer.sanitize(hr)).toBe(hr);
    expect(sanitizer.sanitize(ol)).toBe(ol);
    expect(sanitizer.sanitize(safeDiv)).toBe(safeDiv);
    expect(sanitizer.sanitize(unsafeDiv)).toBe(strippedDiv);
  });

  test('trims a string', () => {
    // tslint:disable-next-line:no-string-literal
    const _trim = new Sanitizer()['_trim'];

    const str = ' \tString\n\r \t';
    const trimmedString = 'String';

    // Save String.prototype.trim
    const trimPrototype = String.prototype.trim;

    // Remove String.prototype.trim for regex path tests
    delete String.prototype.trim;

    // Using regex
    expect(_trim(str)).toBe(trimmedString);
    expect(_trim(trimmedString)).toBe(trimmedString);

    // Return trim to String prototype
    String.prototype.trim = trimPrototype;

    // Using String.prototype.trim
    expect(_trim(str)).toBe(trimmedString);
    expect(_trim(trimmedString)).toBe(trimmedString);
  });
});
