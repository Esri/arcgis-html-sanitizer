import { Sanitizer } from './index';

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

  test('sanitizes invalid html', () => {
    const basicString = 'Hello World';
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';
    const sanitizedInvalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" />';

    const sanitizer = new Sanitizer();

    expect(sanitizer.sanitize(basicString)).toBe(basicString);
    expect(sanitizer.sanitize(validHtml)).toBe(validHtml);
    expect(sanitizer.sanitize(invalidHtml)).toBe(sanitizedInvalidHtml);
  });

  test('checks if string is valid html', () => {
    const basicString = 'Hello World';
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';

    const sanitizer = new Sanitizer();

    expect(sanitizer.isValidHtml(basicString)).toBe(true);
    expect(sanitizer.isValidHtml(validHtml)).toBe(true);
    expect(sanitizer.isValidHtml(invalidHtml)).toBe(false);
  });

  test('extends an object of array by concatenating arrays', () => {
    // tslint:disable-next-line:no-string-literal
    const privateExtend = new Sanitizer()['_extendObjectOfArrays'];

    const result = privateExtend([
      { a: [1, 2] },
      { a: [3, 4], b: [1, 2] },
      { b: [3, 4] }
    ]);

    expect(result).toEqual({ a: [1, 2, 3, 4], b: [1, 2, 3, 4] });
  });
});
