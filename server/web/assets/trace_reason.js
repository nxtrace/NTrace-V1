(function(root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.nextTraceReason = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  const labels = {
    cn: {
      destination_reached: '已到达目标',
      unreachable: '网络不可达',
      max_hops: '已达到最大跳数',
      unknown: '未知原因',
    },
    en: {
      destination_reached: 'Destination reached',
      unreachable: 'Network unreachable',
      max_hops: 'Maximum hops reached',
      unknown: 'Unknown reason',
    },
  };

  function format(reason, lang) {
    if (!reason) {
      return '';
    }
    const texts = labels[lang] || labels.en;
    const parts = [`#${Number(reason.hop) || '?'}`, texts[reason.reason] || texts.unknown];
    if (Array.isArray(reason.responses) && reason.responses.length > 0) {
      parts.push(reason.responses.join(', '));
    }
    if (Array.isArray(reason.markers) && reason.markers.length > 0) {
      parts.push(reason.markers.join(' '));
    }
    return parts.join(' — ');
  }

  return {format};
});
