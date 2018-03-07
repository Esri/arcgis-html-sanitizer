import xss from 'xss';

export class Sanitizer {
  private xssFilter: XSS.ICSSFilter;
  private readonly arcgisFilterOptions: XSS.IFilterXSSOptions = {
    whiteList: {
      a: ['href', 'target', 'style'],
      img: ['src', 'width', 'height', 'border', 'alt', 'style'],
      video: [
        'autoplay',
        'controls',
        'height',
        'loop',
        'muted',
        'poster',
        'preload',
        'src',
        'width'
      ],
      audio: ['autoplay', 'controls', 'loop', 'muted', 'preload', 'src'],
      span: ['style'],
      table: [
        'width',
        'height',
        'cellpadding',
        'cellspacing',
        'border',
        'style'
      ],
      div: ['style', 'class'],
      font: ['size', 'color', 'style'],
      tr: ['height', 'valign', 'align', 'style'],
      td: [
        'height',
        'width',
        'valign',
        'align',
        'colspan',
        'rowspan',
        'nowrap',
        'style'
      ],
      th: [
        'height',
        'width',
        'valign',
        'align',
        'colspan',
        'rowspan',
        'nowrap',
        'style'
      ],
      b: [],
      strong: [],
      i: [],
      em: [],
      br: [],
      p: [],
      li: [],
      ul: [],
      tbody: []
    }
  };

  constructor() {
    this.xssFilter = new xss.FilterXSS(this.arcgisFilterOptions);
  }

  /**
   * Sanitizes a string to remove invalid HTML tags.
   *
   * @param {string} htmlString The string to sanitize.
   * @returns {string} A string with the invalid HTML removed.
   * @memberof Sanitizer
   */
  public sanitize(htmlString: string): string {
    return this.xssFilter.process(htmlString);
  }

  /**
   * Checks if a string only contains valid HTML.
   *
   * @param {string} htmlString The string to validate.
   * @returns {boolean}
   * @memberof Sanitizer
   */
  public isValidHtml(htmlString: string): boolean {
    return htmlString === this.sanitize(htmlString);
  }
}
