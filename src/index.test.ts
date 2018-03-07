import { Sanitizer } from './index';

describe('Sanitizer', () => {
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
});
