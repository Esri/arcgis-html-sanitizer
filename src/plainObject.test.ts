// import ldIsPlainObject from "lodash.isplainobject";
import isPlainObject from "./plainObject";

describe("isPlainObject", () => {
  // @ts-ignore
  function Foo() {
    // @ts-ignore
    this.a = 1;
  }

  // @ts-ignore
  const Bar = () => {
    // @ts-ignore
    const b = 1;
  };

  test("Test truthy values", () => {
    // plain objects
    expect(isPlainObject({})).toBeTruthy();
    expect(isPlainObject({ x: 0, y: 0 })).toBeTruthy();
    expect(isPlainObject({ constructor: Foo })).toBeTruthy();
    expect(isPlainObject(new Object())).toBeTruthy();
    expect(isPlainObject(new Object(null))).toBeTruthy();
    expect(isPlainObject(new Proxy({}, {}))).toBeTruthy();

    // objects with `[[Prototype]]` of `null`
    const nullPrototypeObj = Object.create(null);
    expect(isPlainObject(nullPrototypeObj)).toBeTruthy();
    nullPrototypeObj.prototype = Object.prototype.constructor;
    expect(isPlainObject(nullPrototypeObj)).toBeTruthy();

    // objects with a `valueOf` property
    expect(isPlainObject({ valueOf: 0 })).toBeTruthy();
  });
  test("Falsey values", () => {
    // plain objects
    expect(isPlainObject([1, 2, 3])).toBeFalsy();

    // non-Object objects
    expect(isPlainObject(Error)).toBeFalsy();
    expect(isPlainObject(Math)).toBeFalsy();
    expect(isPlainObject(function* generator() {})).toBeFalsy();
    expect(
      isPlainObject({ a: 1, b: 2, __proto__: { b: 3, c: 4 } })
    ).toBeFalsy();
    expect(isPlainObject(new Date())).toBeFalsy();
    expect(isPlainObject(new Map())).toBeFalsy();
    expect(isPlainObject(new WeakMap())).toBeFalsy();
    expect(isPlainObject(new Set())).toBeFalsy();
    expect(isPlainObject(new WeakSet())).toBeFalsy();
    expect(isPlainObject(Symbol())).toBeFalsy();
    expect(isPlainObject(Foo)).toBeFalsy();
    expect(isPlainObject(Bar)).toBeFalsy();
    expect(isPlainObject(JSON)).toBeFalsy();
    expect(isPlainObject(new RegExp(""))).toBeFalsy();
    expect(
      isPlainObject(
        new Promise<void>((resolve) => {
          resolve();
        })
      )
    ).toBeFalsy();

    expect(isPlainObject(new DataView(new ArrayBuffer(0)))).toBeFalsy();

    // non-objects
    expect(isPlainObject(null)).toBeFalsy();
    expect(isPlainObject(undefined)).toBeFalsy();
    expect(isPlainObject(NaN)).toBeFalsy();
    expect(isPlainObject(Infinity)).toBeFalsy();
    expect(isPlainObject(true)).toBeFalsy();
    expect(isPlainObject(false)).toBeFalsy();
    expect(isPlainObject("")).toBeFalsy();
    expect(isPlainObject("e")).toBeFalsy();
    expect(isPlainObject(1)).toBeFalsy();
  });
});
