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

function escapeHtml(value) {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function getClusterProxy(data) {
    return typeof data?.cluster_proxy === 'object' ? (data.cluster_proxy ?? {}) : {};
}

function buildPlayersByNodeRows(playersByNode) {
    return Object.keys(playersByNode)
        .map((nid) => {
            const count = Number(playersByNode[nid]);
            return `<div class="col-md-4 col-6"><p>Players on node ${escapeHtml(nid)}:</p><strong>${Number.isFinite(count) ? count : 0}</strong></div>`;
        })
        .join('');
}

function buildClusterRows(clusterEnabled, data, clusterProxy, relayMbps, playersByNode) {
    if (!clusterEnabled) {
        return '';
    }
    const tagged = data.owner_node_id !== undefined
        || data.cluster_proxy !== undefined
        || Object.keys(playersByNode).length > 0
        || Number.isFinite(relayMbps);
    if (!tagged) {
        return '';
    }

    const ownerNode = data.owner_node_id !== undefined && data.owner_node_id !== null
        ? data.owner_node_id
        : clusterProxy.owner_node_id;
    const ownerLabel = ownerNode === undefined || ownerNode === null
        ? 'unavailable'
        : escapeHtml(ownerNode);
    const relayLabel = Number.isFinite(relayMbps)
        ? `${relayMbps.toFixed(1)} Mbps`
        : 'n/a';
    const playerByNodeRows = buildPlayersByNodeRows(playersByNode);

    return `<div class="col-md-4 col-6"><p>Owner node:</p><strong>${ownerLabel}</strong></div>
       <div class="col-md-4 col-6"><p>Relay bandwidth:</p><strong>${relayLabel}</strong></div>
       ${playerByNodeRows}`;
}

function buildPlayerRows(players) {
    return players
        .map((pl, index) => {
            const plRtt = Number(pl.rtt_ms);
            if (!Number.isFinite(plRtt) || plRtt <= 0) {
                return '';
            }
            const label = players.length > 1 ? `Player ${index + 1} RTT` : 'Player RTT';
            return `<div class="col-md-4 col-6"><p>${escapeHtml(label)}:</p><strong>${plRtt.toFixed(1)} ms</strong></div>`;
        })
        .join('');
}

function renderStats(statsContainer, data) {
    if (data.error) {
        statsContainer.innerHTML = `<p class="text-danger">${escapeHtml(data.error)}</p>`;
        return;
    }

    const streams = Array.isArray(data.streams) ? data.streams : [];
    if (streams.length === 0) {
        statsContainer.innerHTML = '<p class="text-muted"><em>Stream offline</em></p>';
        return;
    }

    const stream = streams[0];
    const video = stream.video || {};
    const bitrate = Number(stream.bitrate_kbps);
    const rtt = Number(stream.rtt_ms);
    const width = Number(video.width);
    const height = Number(video.height);
    const fps = Number(video.fps);
    const players = Number((data.summary || {}).players);
    const clusterEnabled = statsContainer.dataset.cluster === '1';
    const clusterProxy = getClusterProxy(data);
    const relayRaw = data.relay_mbps ?? clusterProxy.relay_mbps;
    const relayMbps = relayRaw === null || relayRaw === undefined
        ? Number.NaN
        : Number(relayRaw);
    const playersByNode = data.players_by_node
        || clusterProxy.players_by_node
        || {};
    const clusterRows = buildClusterRows(
        clusterEnabled,
        data,
        clusterProxy,
        relayMbps,
        playersByNode,
    );
    const playerRows = buildPlayerRows(Array.isArray(data.players) ? data.players : []);

    statsContainer.innerHTML = `
        <div class="mt-2 p-2 bg-dark bg-opacity-50 rounded">
            <h6 class="mb-2">Stream Statistics</h6>
            <div class="row g-2">
                <div class="col-md-4 col-6">
                    <p>Bitrate:</p>
                    <strong>${Number.isFinite(bitrate) ? bitrate.toFixed(1) : '0.0'} kbps</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>Publisher RTT:</p>
                    <strong>${Number.isFinite(rtt) && rtt > 0 ? `${rtt.toFixed(1)} ms` : 'n/a'}</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>Uptime:</p>
                    <strong>${formatUptime(stream.uptime || 0)}</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>Codec:</p>
                    <strong>${escapeHtml(video.codec || 'n/a')}</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>Resolution:</p>
                    <strong>${Number.isFinite(width) ? width : 0}x${Number.isFinite(height) ? height : 0}</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>FPS:</p>
                    <strong>${Number.isFinite(fps) ? fps : 0}</strong>
                </div>
                <div class="col-md-4 col-6">
                    <p>Players:</p>
                    <strong>${Number.isFinite(players) ? players : 0}</strong>
                </div>
                ${clusterRows}
                ${playerRows}
            </div>
        </div>
    `;
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
            statsContainer.innerHTML = '<p><em>Stats not available</em></p>';
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
