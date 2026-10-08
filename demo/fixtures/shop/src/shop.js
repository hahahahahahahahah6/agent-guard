export function getPage({ page }) {
  const items = Array.from({ length: 10 }, (_, i) => ({ id: i }));
  return { page, items };
}
