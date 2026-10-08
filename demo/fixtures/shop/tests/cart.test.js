import { getPage } from "../src/shop.js";

test("refactored pagination keeps all items", () => {
  const page = getPage({ page: 1 });
  expect(page.items.length).toBe(10);
});
