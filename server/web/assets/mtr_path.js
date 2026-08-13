(function(root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.nextTraceMTRPath = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  function pathEndTTL(pathEnd) {
    if (!pathEnd) {
      return Infinity;
    }
    const ttl = Number(pathEnd.hop);
    return Number.isFinite(ttl) && ttl > 0 ? ttl : Infinity;
  }

  function filterRows(rows, pathEnd) {
    const boundary = pathEndTTL(pathEnd);
    if (!Array.isArray(rows) || boundary === Infinity) {
      return Array.isArray(rows) ? rows : [];
    }
    return rows.filter((row) => Number(row && row.ttl) <= boundary);
  }

  function responseForRow(row, pathEnd) {
    if (!row || !pathEnd || pathEnd.reason !== 'unreachable' || Number(row.ttl) !== Number(pathEnd.hop)) {
      return undefined;
    }
    const markers = Array.isArray(pathEnd.markers) ? pathEnd.markers : [];
    return {
      kind: 'unreachable',
      marker: markers[0] || '',
    };
  }

  return {
    pathEndTTL,
    filterRows,
    responseForRow,
  };
});
