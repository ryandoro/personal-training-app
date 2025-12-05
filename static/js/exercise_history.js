(function (window, document) {
    'use strict';

    const contexts = [];
    const DEFAULT_LINE_COLOR = '#F7931A';
    const DEFAULT_FILL_COLOR = 'rgba(247, 147, 26, 0.15)';

    function computeOneRepMax(weight, reps) {
        const parsedWeight = Number.parseFloat(weight);
        const parsedReps = Number.parseFloat(reps);
        if (!Number.isFinite(parsedWeight) || !Number.isFinite(parsedReps)) {
            return null;
        }
        if (parsedWeight <= 0 || parsedReps <= 0) {
            return null;
        }
        return Number((parsedWeight * (1 + 0.0333 * parsedReps)).toFixed(1));
    }

    function formatOneRepMax(value) {
        if (!Number.isFinite(value)) {
            return '—';
        }
        const rounded = Math.round(value);
        return `${rounded} lbs`;
    }

    function formatWeight(value) {
        if (!Number.isFinite(value)) {
            return null;
        }
        return `${Number(value).toFixed(1)} lbs`;
    }

    function formatReps(value) {
        if (!Number.isFinite(value)) {
            return null;
        }
        return `${Math.round(value)} reps`;
    }

    function formatDateLabel(isoString) {
        if (!isoString) return '—';
        const timestamp = Date.parse(isoString);
        if (Number.isNaN(timestamp)) return '—';
        const date = new Date(timestamp);
        return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }

    function destroyChart(canvas) {
        if (canvas && canvas._fitbaseChart) {
            canvas._fitbaseChart.destroy();
            delete canvas._fitbaseChart;
        }
    }

    function togglePlaceholder(wrapper, hidden, message) {
        if (!wrapper) return;
        if (typeof message === 'string') {
            wrapper.textContent = message;
        }
        wrapper.style.display = hidden ? 'none' : '';
    }

    function formatCardioTime(value) {
        if (!Number.isFinite(value)) {
            return '—';
        }
        const rounded = Math.round(value * 10) / 10;
        const display = Number.isInteger(rounded) ? rounded.toString() : rounded.toFixed(1);
        return `${display} min`;
    }

    function updateMetricDisplay(card, payload) {
        const metricNodes = card.querySelectorAll(`[data-metric-value][data-workout-id="${card.dataset.workoutCard}"]`);
        if (!metricNodes.length) return;
        const isCardio = !!payload.is_cardio;
        const summary = payload.summary || {};
        const latestOneRm = summary.latest_one_rm;
        const bestValue = summary.best_value;
        metricNodes.forEach((node) => {
            if (isCardio) {
                const numericBest = Number(bestValue);
                if (Number.isFinite(numericBest) && numericBest > 0) {
                    node.textContent = formatCardioTime(numericBest);
                    node.dataset.value = String(numericBest);
                } else {
                    node.textContent = '—';
                    node.dataset.value = '';
                }
                return;
            }
            if (Number.isFinite(latestOneRm)) {
                node.textContent = formatOneRepMax(latestOneRm);
                node.dataset.value = String(latestOneRm);
            } else {
                node.textContent = '—';
                node.dataset.value = '';
            }
        });
    }

function renderChart(card, payload, placeholder, canvas) {
    if (!window.Chart || !canvas) return;
    const history = Array.isArray(payload.history) ? payload.history : [];
        const labels = [];
        const values = [];

        history.forEach((entry) => {
            const displayValue = typeof entry.display_value === 'number' ? entry.display_value : NaN;
            labels.push(formatDateLabel(entry.recorded_at));
            values.push(Number.isFinite(displayValue) ? Number(displayValue.toFixed(2)) : null);
        });

        const hasValue = values.some((val) => typeof val === 'number');
    if (!hasValue) {
        destroyChart(canvas);
        togglePlaceholder(placeholder, false, 'Log a new max to unlock this chart.');
        return;
    }

        const ctx = canvas.getContext('2d');
        destroyChart(canvas);

        canvas._fitbaseChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        data: values,
                        label: payload.chart_label || 'Progress',
                        borderColor: DEFAULT_LINE_COLOR,
                        backgroundColor: DEFAULT_FILL_COLOR,
                        pointRadius: 3,
                        pointHoverRadius: 5,
                        pointHitRadius: 10,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.25,
                        spanGaps: true,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: (val) => `${val} ${payload.chart_unit || ''}`.trim(),
                        },
                    },
                    x: {
                        ticks: {
                            maxTicksLimit: 6,
                        },
                    },
                },
                plugins: {
                    legend: {
                        display: false,
                    },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const entry = history[ctx.dataIndex] || {};
                                const val = ctx.parsed.y;
                                const unit = payload.chart_unit || '';
                                if (!Number.isFinite(val)) return 'No data';
                                const base = `${val} ${unit}`.trim();
                                if (payload.is_cardio) {
                                    const duration = Number.isFinite(entry.display_value)
                                        ? formatCardioTime(entry.display_value)
                                        : '—';
                                    return [`${base}`, `Time: ${duration}`];
                                }
                                const weightLine = formatWeight(entry.weight);
                                const repsLine = formatReps(entry.reps);
                                const lines = [base];
                                if (weightLine) lines.push(`Weight: ${weightLine}`);
                                if (repsLine) lines.push(`Reps: ${repsLine}`);
                                return lines;
                            },
                        },
                    },
                },
            },
        });
        togglePlaceholder(placeholder, true);
    }

    function hydrateCard(card, context, options = {}) {
        if (!card || !context || !context.historyUrl || !window.Chart) return;
        const wrapper = card.querySelector('[data-progress-chart]');
        const placeholder = wrapper?.querySelector('.chart-placeholder');
        const canvas = wrapper?.querySelector('canvas');
        if (!wrapper || !canvas) return;
        if (!options.force && card.dataset.chartLoaded === 'true') {
            return;
        }

        const params = new URLSearchParams();
        params.set('workout_id', card.dataset.workoutCard || '');
        const cardClientId = card.dataset.clientId || context.clientId;
        if (cardClientId) {
            params.set('client_id', cardClientId);
        }
        const windowKey = (card.dataset.historyWindow || context.defaultWindow || '90d').toLowerCase();
        params.set('window', windowKey);

        fetch(`${context.historyUrl}?${params.toString()}`, { credentials: 'same-origin' })
            .then(async (response) => {
                const payload = await response.json().catch(() => null);
                if (!response.ok) {
                    throw new Error(payload?.error || 'Unable to load history.');
                }
                return payload;
            })
            .then((payload) => {
                if (!payload?.success) {
                    togglePlaceholder(placeholder, false, payload?.error || 'No history yet.');
                    destroyChart(canvas);
                    return;
                }
                updateMetricDisplay(card, payload);
                renderChart(card, payload, placeholder, canvas);
                const resolvedWindow = payload.window || windowKey;
                if (resolvedWindow !== card.dataset.historyWindow) {
                    card.dataset.historyWindow = resolvedWindow;
                    if (card.dataset.windowControlsBound === 'true') {
                        card.dispatchEvent(new CustomEvent('history-window-change', { detail: { window: resolvedWindow } }));
                    }
                }
            })
            .catch((error) => {
                console.warn(error);
                destroyChart(canvas);
                togglePlaceholder(placeholder, false, 'Unable to load history.');
            })
            .finally(() => {
                card.dataset.chartLoaded = 'true';
            });
    }

    function bindWindowControls(card, context) {
        if (!card || card.dataset.windowControlsBound === 'true') return;
        const buttons = card.querySelectorAll('.chart-window-btn');
        if (!buttons.length) return;
        const setActive = (activeWindow) => {
            buttons.forEach((btn) => {
                btn.classList.toggle('active', btn.dataset.window === activeWindow);
            });
        };
        buttons.forEach((btn) => {
            btn.addEventListener('click', (event) => {
                event.preventDefault();
                const windowValue = (btn.dataset.window || '').toLowerCase();
                if (!windowValue || card.dataset.historyWindow === windowValue) {
                    return;
                }
                card.dataset.historyWindow = windowValue;
                card.dataset.chartLoaded = 'false';
                setActive(windowValue);
                hydrateCard(card, context, { force: true });
            });
        });
        card.addEventListener('history-window-change', (event) => {
            const newWindow = event.detail?.window;
            if (!newWindow) return;
            setActive(newWindow);
        });
        const initialWindow = card.dataset.historyWindow || context.defaultWindow || '90d';
        card.dataset.historyWindow = initialWindow;
        setActive(initialWindow);
        card.dataset.windowControlsBound = 'true';
    }

    function registerContext(config) {
        const context = {
            id: contexts.length,
            historyUrl: config.historyUrl,
            clientId: config.clientId || null,
            cardSelector: config.cardSelector || '[data-workout-card]',
            defaultWindow: (config.defaultWindow || '90d').toLowerCase(),
        };
        contexts.push(context);
        return context;
    }

    function initCharts(config = {}) {
        if (!config.historyUrl) return;
        if (!window.Chart) {
            console.warn('Chart.js is required for exercise history charts.');
            return;
        }
        const context = registerContext(config);
        document.querySelectorAll(context.cardSelector).forEach((card) => {
            if (!card.dataset.workoutCard) return;
            card.dataset.historyContext = String(context.id);
            if (!card.dataset.historyWindow) {
                card.dataset.historyWindow = context.defaultWindow;
            }
            bindWindowControls(card, context);
            hydrateCard(card, context);
        });
    }

    function refreshHistory(workoutId) {
        if (!workoutId) return;
        const selector = `[data-workout-card="${workoutId}"]`;
        document.querySelectorAll(selector).forEach((card) => {
            const contextId = Number(card.dataset.historyContext);
            const context = contexts[contextId];
            if (!context) return;
            hydrateCard(card, context, { force: true });
        });
    }

    const FitBaseExerciseHistory = window.FitBaseExerciseHistory || {};
    FitBaseExerciseHistory.initCharts = initCharts;
    FitBaseExerciseHistory.refreshHistory = refreshHistory;
    FitBaseExerciseHistory.computeOneRepMax = computeOneRepMax;
    FitBaseExerciseHistory.formatOneRepMax = formatOneRepMax;
    window.FitBaseExerciseHistory = FitBaseExerciseHistory;
})(window, document);
