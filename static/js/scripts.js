document.addEventListener('DOMContentLoaded', function () {
    initializeStats();
    document.querySelectorAll('.cluster-remove-form').forEach((form) => {
        form.addEventListener('submit', (event) => {
            const nodeId = form.dataset.nodeId || '';
            const message = `Remove node ${nodeId} from the cluster? This cannot be undone from the panel.`;
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });
});

async function copyToClipboard(element) {
    const text = element.dataset.url || '';
    try {
        await navigator.clipboard.writeText(text);
        showCopyFeedback(element, 'Copied');
    } catch (err) {
        console.warn('Clipboard write failed', err);
        showCopyFeedback(element, 'Copy failed');
    }
}

function showCopyFeedback(element, text) {
    const feedback = element.nextElementSibling;
    if (feedback) {
        feedback.textContent = text;
        feedback.classList.add('visible');
        setTimeout(() => {
            feedback.textContent = '';
            feedback.classList.remove('visible');
        }, 2000);
    }
}

function initializeStats() {
    const statsContainers = Array.from(document.querySelectorAll('[id^="stats-"]'));
    if (statsContainers.length === 0) {
        return;
    }

    const isVisible = (container) => {
        const collapse = container.closest('.accordion-collapse');
        return !collapse || collapse.classList.contains('show');
    };

    const loadVisibleStats = () => {
        if (document.hidden) {
            return;
        }
        statsContainers.forEach(container => {
            if (!isVisible(container)) {
                return;
            }
            const streamId = container.dataset.streamId;
            if (streamId) {
                loadStats(streamId);
            }
        });
    };

    document.querySelectorAll('.accordion-collapse').forEach(collapse => {
        collapse.addEventListener('shown.bs.collapse', loadVisibleStats);
    });
    document.addEventListener('visibilitychange', loadVisibleStats);

    loadVisibleStats();
    setInterval(loadVisibleStats, 3000);
}

function createStatColumn(label, value) {
    const column = document.createElement('div');
    column.className = 'col-md-4 col-6';

    const paragraph = document.createElement('p');
    paragraph.textContent = label;

    const strong = document.createElement('strong');
    strong.textContent = String(value);

    column.append(paragraph, strong);
    return column;
}

function getClusterProxy(data) {
    return typeof data?.cluster_proxy === 'object' ? (data.cluster_proxy ?? {}) : {};
}

function buildPlayersByNodeRows(playersByNode) {
    return Object.keys(playersByNode).map((nid) => {
        const count = Number(playersByNode[nid]);
        return createStatColumn(
            `Players on node ${nid}:`,
            Number.isFinite(count) ? count : 0,
        );
    });
}

function buildClusterRows(clusterEnabled, data, clusterProxy, relayMbps, playersByNode) {
    if (!clusterEnabled) {
        return [];
    }
    const tagged = data.owner_node_id !== undefined
        || data.cluster_proxy !== undefined
        || Object.keys(playersByNode).length > 0
        || Number.isFinite(relayMbps);
    if (!tagged) {
        return [];
    }

    const ownerNode = data.owner_node_id !== undefined && data.owner_node_id !== null
        ? data.owner_node_id
        : clusterProxy.owner_node_id;
    const ownerLabel = ownerNode === undefined || ownerNode === null
        ? 'unavailable'
        : ownerNode;
    const relayLabel = Number.isFinite(relayMbps)
        ? `${relayMbps.toFixed(1)} Mbps`
        : 'n/a';

    return [
        createStatColumn('Owner node:', ownerLabel),
        createStatColumn('Relay bandwidth:', relayLabel),
        ...buildPlayersByNodeRows(playersByNode),
    ];
}

function buildPlayerRows(players) {
    return players
        .map((pl, index) => {
            const plRtt = Number(pl.rtt_ms);
            if (!Number.isFinite(plRtt) || plRtt <= 0) {
                return null;
            }
            const label = players.length > 1 ? `Player ${index + 1} RTT` : 'Player RTT';
            return createStatColumn(`${label}:`, `${plRtt.toFixed(1)} ms`);
        })
        .filter(Boolean);
}

function resolveStreamVideo(row) {
    if (row.video && typeof row.video === 'object') {
        return row.video;
    }
    return {
        codec: row.video_codec || 'n/a',
        width: row.video_width,
        height: row.video_height,
        fps: row.fps,
    };
}

function resolveStreamUptime(row) {
    if (row.uptime !== undefined) {
        return row.uptime;
    }
    if (row.connected_at === null) {
        return null;
    }
    const connectedAt = Number(row.connected_at);
    if (!Number.isFinite(connectedAt)) {
        return 0;
    }
    return Math.max(0, Math.floor(Date.now() / 1000) - connectedAt);
}

function proxiedStreamRow(row) {
    if (!row || typeof row !== 'object') {
        return {};
    }
    return {
        id: row.id || row.stream_id,
        name: row.name || row.stream_name || row.stream_id || '',
        app: row.app,
        uptime: resolveStreamUptime(row),
        bitrate_kbps: row.bitrate_kbps,
        rtt_ms: row.rtt_ms,
        video: resolveStreamVideo(row),
        audio: row.audio || { codec: row.audio_codec || 'n/a' },
    };
}

function renderStatsPlaceholder(statsContainer, text, className) {
    const placeholder = document.createElement('p');
    placeholder.className = className;
    const emphasis = document.createElement('em');
    emphasis.textContent = text;
    placeholder.append(emphasis);
    statsContainer.replaceChildren(placeholder);
}

function resolveRelayMbps(data, clusterProxy) {
    const relayRaw = data.relay_mbps ?? clusterProxy.relay_mbps;
    return relayRaw === null || relayRaw === undefined
        ? Number.NaN
        : Number(relayRaw);
}

function resolvePlayerRows(data, clusterProxy) {
    const local = Array.isArray(data.players) ? data.players : [];
    if (local.length > 0) {
        return local;
    }
    return Array.isArray(clusterProxy.player_rows) ? clusterProxy.player_rows : [];
}

function resolvePlayers(data, clusterProxy, proxyOnly) {
    // On a non-owner node the local summary reports 0 players; prefer the
    // proxied owner metric for a proxy-only stream.
    if (proxyOnly) {
        return Number(clusterProxy.players ?? data.summary?.players);
    }
    return Number(data.summary?.players ?? clusterProxy.players);
}

function resolvePlayersByNode(data, clusterProxy, proxyOnly) {
    if (proxyOnly) {
        return clusterProxy.players_by_node || data.players_by_node || {};
    }
    return data.players_by_node || clusterProxy.players_by_node || {};
}

function buildStatsRows(stream, video, players, clusterRows, playerRows) {
    const bitrate = Number(stream.bitrate_kbps);
    const rtt = Number(stream.rtt_ms);
    const width = Number(video.width);
    const height = Number(video.height);
    const fps = Number(video.fps);
    const rows = document.createElement('div');
    rows.className = 'row g-2';
    rows.append(
        createStatColumn(
            'Bitrate:',
            `${Number.isFinite(bitrate) ? bitrate.toFixed(1) : '0.0'} kbps`,
        ),
        createStatColumn(
            'Publisher RTT:',
            Number.isFinite(rtt) && rtt > 0 ? `${rtt.toFixed(1)} ms` : 'n/a',
        ),
        createStatColumn(
            'Uptime:',
            stream.uptime === null ? 'n/a' : formatUptime(stream.uptime || 0),
        ),
        createStatColumn('Codec:', video.codec || 'n/a'),
        createStatColumn(
            'Resolution:',
            `${Number.isFinite(width) ? width : 0}x${Number.isFinite(height) ? height : 0}`,
        ),
        createStatColumn('FPS:', Number.isFinite(fps) ? fps : 0),
        createStatColumn('Players:', Number.isFinite(players) ? players : 0),
        ...clusterRows,
        ...playerRows,
    );
    return rows;
}

function renderStats(statsContainer, data) {
    if (data.error) {
        const error = document.createElement('p');
        error.className = 'text-danger';
        error.textContent = String(data.error);
        statsContainer.replaceChildren(error);
        return;
    }

    const streams = Array.isArray(data.streams) ? data.streams : [];
    const clusterProxy = getClusterProxy(data);
    const proxiedPublisherRows = Array.isArray(clusterProxy.publisher_rows)
        ? clusterProxy.publisher_rows
        : [];
    if (streams.length === 0 && proxiedPublisherRows.length === 0) {
        renderStatsPlaceholder(statsContainer, 'Stream offline', 'text-muted');
        return;
    }

    // The owner node's publisher rows are proxied in cluster_proxy when this
    // node does not host the stream, so a live remote stream is not offline.
    const stream = streams[0] || proxiedStreamRow(proxiedPublisherRows[0]);
    const proxyOnly = streams.length === 0;
    const players = resolvePlayers(data, clusterProxy, proxyOnly);
    const playersByNode = resolvePlayersByNode(data, clusterProxy, proxyOnly);
    const clusterRows = buildClusterRows(
        statsContainer.dataset.cluster === '1',
        data,
        clusterProxy,
        resolveRelayMbps(data, clusterProxy),
        playersByNode,
    );
    const playerRows = buildPlayerRows(resolvePlayerRows(data, clusterProxy));

    const wrapper = document.createElement('div');
    wrapper.className = 'mt-2 p-2 bg-dark bg-opacity-50 rounded';

    const title = document.createElement('h6');
    title.className = 'mb-2';
    title.textContent = 'Stream Statistics';

    wrapper.append(
        title,
        buildStatsRows(stream, stream.video || {}, players, clusterRows, playerRows),
    );
    statsContainer.replaceChildren(wrapper);
}

function loadStats(streamId) {
    const statsContainer = document.getElementById(`stats-${streamId}`);
    if (!statsContainer || statsContainer.dataset.loading === 'true') {
        return;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    statsContainer.dataset.loading = 'true';
    fetch(`/streams/${encodeURIComponent(streamId)}/stats.json`, {
        signal: controller.signal,
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => renderStats(statsContainer, data))
        .catch((err) => {
            console.warn('Stats request failed', err);
            const unavailable = document.createElement('p');
            const emphasis = document.createElement('em');
            emphasis.textContent = 'Stats not available';
            unavailable.append(emphasis);
            statsContainer.replaceChildren(unavailable);
        })
        .finally(() => {
            clearTimeout(timeoutId);
            delete statsContainer.dataset.loading;
        });
}

function formatUptime(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) return '00:00:00';
    seconds = Math.floor(value);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    const time = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    return days > 0 ? `${days}d ${time}` : time;
}
