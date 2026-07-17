document.addEventListener('DOMContentLoaded', function () {
    initializeStats();
});

async function copyToClipboard(element) {
    const text = element.getAttribute('data-url');
    try {
        await navigator.clipboard.writeText(text);
        showCopyFeedback(element, 'Copied');
    } catch (err) {
        copyToClipboardFallback(text, element);
    }
}

function copyToClipboardFallback(text, element) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.cssText = 'position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;box-shadow:none;background:transparent;opacity:0;';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        const successful = document.execCommand('copy');
        showCopyFeedback(element, successful ? 'Copied' : 'Copy failed');
    } catch (err) {
        showCopyFeedback(element, 'Copy failed');
    } finally {
        document.body.removeChild(textArea);
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
    const statsContainers = document.querySelectorAll('[id^="stats-"]');
    if (statsContainers.length === 0) {
        return;
    }
    const tick = () => statsContainers.forEach(container => {
        const streamId = container.dataset.streamId;
        if (streamId) {
            loadStats(streamId);
        }
    });
    tick();
    setInterval(tick, 3000);
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function loadStats(streamId) {
    const statsContainer = document.getElementById(`stats-${streamId}`);
    if (!statsContainer) {
        return;
    }
    fetch(`/streams/${streamId}/stats.json`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                statsContainer.innerHTML = `<p class="text-danger">${escapeHtml(data.error)}</p>`;
                return;
            }
            const streams = data.streams || [];
            if (streams.length === 0) {
                statsContainer.innerHTML = `<p class="text-muted"><em>Stream offline</em></p>`;
                return;
            }
            const s = streams[0];
            const video = s.video || {};
            const bitrate = Number(s.bitrate_kbps);
            const rtt = Number(s.rtt_ms);
            const width = Number(video.width);
            const height = Number(video.height);
            const fps = Number(video.fps);
            const players = Number((data.summary || {}).players);
            // buffer_bytes / latency_ms / dropped_pkts are not emitted by
            // every librtmp2-server build yet (see librtmp2 CHANGELOG for
            // Conn::buffer_bytes()/latency_ms() and Server::backpressure_drops).
            // Render "n/a" rather than a stale/misleading zero when absent.
            const bufferBytes = Number(s.buffer_bytes);
            const latency = Number(s.latency_ms);
            const droppedPkts = Number((data.summary || {}).dropped_pkts);
            const playerRows = (data.players || [])
                .map((pl, index) => {
                    const plRtt = Number(pl.rtt_ms);
                    if (!Number.isFinite(plRtt) || plRtt <= 0) {
                        return '';
                    }
                    const label = data.players.length > 1 ? `Player ${index + 1} RTT` : 'Player RTT';
                    return `<div class="col-md-4 col-6"><p>${escapeHtml(label)}:</p><strong>${plRtt.toFixed(1)} ms</strong></div>`;
                })
                .join('');
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
                            <strong>${formatUptime(s.uptime || 0)}</strong>
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
                        <div class="col-md-4 col-6">
                            <p>Buffer:</p>
                            <strong>${Number.isFinite(bufferBytes) ? `${(bufferBytes / 1024).toFixed(1)} KB` : 'n/a'}</strong>
                        </div>
                        <div class="col-md-4 col-6">
                            <p>Latency (est.):</p>
                            <strong>${Number.isFinite(latency) ? `${latency.toFixed(1)} ms` : 'n/a'}</strong>
                        </div>
                        <div class="col-md-4 col-6">
                            <p>Dropped (backpressure):</p>
                            <strong>${Number.isFinite(droppedPkts) ? droppedPkts : 'n/a'}</strong>
                        </div>
                        ${playerRows}
                    </div>
                </div>
            `;
        })
        .catch(() => {
            statsContainer.innerHTML = `<p><em>Stats not available</em></p>`;
        });
}

function formatUptime(seconds) {
    if (!seconds || seconds < 0) return '00:00:00';
    seconds = Math.floor(seconds);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    const time = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    return days > 0 ? `${days}d ${time}` : time;
}
