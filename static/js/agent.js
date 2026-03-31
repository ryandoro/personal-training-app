(function () {
    const configNode = document.getElementById('fitbase-agent-config');
    let config = window.fitBaseAgentConfig || null;
    if (!config && configNode) {
        try {
            config = JSON.parse(configNode.textContent || '{}');
        } catch (error) {
            console.error('Unable to parse FitBaseAI config', error);
        }
    }
    if (!config || !config.userId) {
        return;
    }

    const shell = document.querySelector('[data-fitbase-shell]');
    const panel = document.querySelector('[data-fitbase-panel]');
    const resizeHandle = document.querySelector('[data-fitbase-resize-handle]');
    const clearHistoryButton = document.querySelector('[data-fitbase-clear-history]');
    const messagesRoot = document.querySelector('[data-fitbase-messages]');
    const form = document.querySelector('[data-fitbase-form]');
    const input = document.querySelector('[data-fitbase-input]');
    const status = document.querySelector('[data-fitbase-status]');
    const sendButton = document.querySelector('[data-fitbase-send]');
    const threadStorageKey = `fitbaseai-thread:${config.userId}`;
    const openStateStorageKey = `fitbaseai-open:${config.userId}`;
    const panelWidthStorageKey = `fitbaseai-width:${config.userId}`;
    const adminStatus = document.querySelector('[data-fitbase-admin-status]');

    if (!shell || !panel || !messagesRoot || !form || !input) {
        return;
    }

    let currentThreadId = window.localStorage.getItem(threadStorageKey) || null;
    let threadLoaded = false;
    let threadLoadPromise = null;
    let sending = false;
    let clearingHistory = false;
    let activeResizePointerId = null;
    let chartLibraryPromise = null;
    let viewportSyncFrame = null;
    const desktopPanelQuery = window.matchMedia('(min-width: 768px)');
    const coarsePointerQuery = window.matchMedia('(pointer: coarse)');
    const DEFAULT_CHART_LINE_COLOR = '#F7931A';
    const DEFAULT_CHART_FILL_COLOR = 'rgba(247, 147, 26, 0.15)';
    const DEFAULT_EMPTY_MESSAGE = 'Ask about your training, schedule, clients, or FitBaseAI metrics. Action tasks must be confirmed before FitBaseAI can complete them.';

    function buildUrl(template, token) {
        return (template || '').replace(/__(THREAD_ID|ACTION_ID)__/, token);
    }

    function ensureChartLibrary() {
        if (window.Chart) {
            return Promise.resolve(window.Chart);
        }
        if (chartLibraryPromise) {
            return chartLibraryPromise;
        }
        chartLibraryPromise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
            script.async = true;
            script.onload = () => resolve(window.Chart);
            script.onerror = () => reject(new Error('Unable to load Chart.js.'));
            document.head.appendChild(script);
        }).catch((error) => {
            chartLibraryPromise = null;
            throw error;
        });
        return chartLibraryPromise;
    }

    function isDesktopPanelMode() {
        return desktopPanelQuery.matches;
    }

    function isTouchViewport() {
        return coarsePointerQuery.matches || navigator.maxTouchPoints > 0;
    }

    function clampPanelWidth(width) {
        const viewportMax = Math.max(320, window.innerWidth - 40);
        const maxWidth = Math.min(860, viewportMax);
        const minWidth = Math.min(360, maxWidth);
        return Math.max(minWidth, Math.min(width, maxWidth));
    }

    function applyPanelWidth(width) {
        if (!isDesktopPanelMode()) {
            panel.style.removeProperty('--fitbaseai-panel-width');
            return null;
        }
        const numericWidth = Number(width);
        if (!Number.isFinite(numericWidth)) {
            panel.style.removeProperty('--fitbaseai-panel-width');
            return null;
        }
        const clampedWidth = clampPanelWidth(numericWidth);
        panel.style.setProperty('--fitbaseai-panel-width', `${Math.round(clampedWidth)}px`);
        return clampedWidth;
    }

    function restoreStoredPanelWidth() {
        const storedWidth = Number(window.localStorage.getItem(panelWidthStorageKey));
        if (Number.isFinite(storedWidth) && storedWidth > 0) {
            applyPanelWidth(storedWidth);
            return;
        }
        applyPanelWidth(panel.getBoundingClientRect().width || 460);
    }

    function setPanelModalState() {
        if (isDesktopPanelMode()) {
            panel.removeAttribute('aria-modal');
        } else {
            panel.setAttribute('aria-modal', 'true');
        }
    }

    function setStatus(message, tone) {
        if (!status) {
            return;
        }
        status.textContent = message || '';
        status.dataset.tone = tone || '';
    }

    function clearViewportSyncState() {
        if (viewportSyncFrame !== null) {
            cancelAnimationFrame(viewportSyncFrame);
            viewportSyncFrame = null;
        }
        shell.style.removeProperty('--fitbaseai-shell-top');
        shell.style.removeProperty('--fitbaseai-shell-height');
        document.body.classList.remove('fitbaseai-keyboard-open');
    }

    function scrollComposerIntoView() {
        requestAnimationFrame(() => {
            if (shell.hidden) {
                return;
            }
            messagesRoot.scrollTop = messagesRoot.scrollHeight;
            input.scrollIntoView({
                block: 'nearest',
                inline: 'nearest'
            });
        });
    }

    function syncShellViewport(options) {
        if (shell.hidden) {
            clearViewportSyncState();
            return;
        }

        const viewport = window.visualViewport;
        if (!viewport) {
            shell.style.removeProperty('--fitbaseai-shell-top');
            shell.style.removeProperty('--fitbaseai-shell-height');
            document.body.classList.remove('fitbaseai-keyboard-open');
            if (options?.keepComposerVisible) {
                scrollComposerIntoView();
            }
            return;
        }

        const viewportTop = Math.max(0, Number(viewport.offsetTop) || 0);
        const viewportHeight = Math.max(0, Number(viewport.height) || window.innerHeight);
        const keyboardInset = Math.max(0, Math.round(window.innerHeight - viewportHeight - viewportTop));

        shell.style.setProperty('--fitbaseai-shell-top', `${Math.round(viewportTop)}px`);
        shell.style.setProperty('--fitbaseai-shell-height', `${Math.round(viewportHeight)}px`);
        document.body.classList.toggle('fitbaseai-keyboard-open', keyboardInset > 120);

        if (options?.keepComposerVisible || document.activeElement === input || keyboardInset > 0) {
            scrollComposerIntoView();
        }
    }

    function scheduleViewportSync(options) {
        const keepComposerVisible = Boolean(options?.keepComposerVisible);
        if (viewportSyncFrame !== null) {
            cancelAnimationFrame(viewportSyncFrame);
        }
        viewportSyncFrame = requestAnimationFrame(() => {
            viewportSyncFrame = null;
            syncShellViewport({ keepComposerVisible });
        });
    }

    function focusInput() {
        try {
            if (isTouchViewport()) {
                input.focus();
            } else {
                input.focus({ preventScroll: true });
            }
        } catch (error) {
            input.focus();
        }
        scheduleViewportSync({ keepComposerVisible: true });
    }

    function selectedClientIdFromPage() {
        const path = window.location.pathname || '';
        const match = path.match(/\/client_profile\/(\d+)/);
        if (match) {
            return Number(match[1]);
        }
        const params = new URLSearchParams(window.location.search);
        const queryId = params.get('client_id') || params.get('selected_client_id');
        return queryId ? Number(queryId) : null;
    }

    function buildPageContext() {
        return {
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
            page_path: window.location.pathname,
            page_title: document.title,
            selected_client_id: selectedClientIdFromPage()
        };
    }

    function clearDefaultMessage() {
        const defaultMessage = messagesRoot.querySelector('.fitbaseai-message--assistant');
        if (defaultMessage && defaultMessage.dataset.seed !== 'persisted') {
            defaultMessage.remove();
        }
    }

    function createDefaultAssistantMessage() {
        const article = document.createElement('article');
        article.className = 'fitbaseai-message fitbaseai-message--assistant';

        const label = document.createElement('div');
        label.className = 'fitbaseai-message__label';
        label.textContent = 'FitBaseAI';
        article.appendChild(label);

        const body = document.createElement('div');
        body.className = 'fitbaseai-message__body';
        body.textContent = DEFAULT_EMPTY_MESSAGE;
        article.appendChild(body);

        return article;
    }

    function resetMessagesToDefault() {
        messagesRoot.querySelectorAll('canvas').forEach((canvas) => {
            destroyExerciseDetailChart(canvas);
        });
        messagesRoot.replaceChildren(createDefaultAssistantMessage());
        messagesRoot.scrollTop = 0;
    }

    function createCitationList(citations) {
        if (!Array.isArray(citations) || citations.length === 0) {
            return null;
        }
        const list = document.createElement('div');
        list.className = 'fitbaseai-citations';
        citations.forEach((citation) => {
            const item = document.createElement('a');
            item.className = 'fitbaseai-citation';
            item.href = citation.url || '#';
            item.target = citation.url ? '_blank' : '_self';
            item.rel = citation.url ? 'noreferrer noopener' : '';
            item.textContent = citation.label || citation.title || 'Source';
            if (!citation.url) {
                item.classList.add('is-disabled');
            }
            list.appendChild(item);
        });
        return list;
    }

    function createPendingActionCard(pendingAction) {
        if (!pendingAction || !pendingAction.id) {
            return null;
        }
        const card = document.createElement('div');
        card.className = 'fitbaseai-action-card';
        card.dataset.actionId = pendingAction.id;
        card.innerHTML = `
            <div class="fitbaseai-action-card__label">${pendingAction.label || 'Pending action'}</div>
            <div class="fitbaseai-action-card__summary">${pendingAction.summary || ''}</div>
            <div class="fitbaseai-action-card__buttons">
                <button type="button" class="btn btn-brand btn-sm" data-fitbase-action-confirm="${pendingAction.id}">Confirm</button>
                <button type="button" class="btn btn-brand-outline btn-sm" data-fitbase-action-cancel="${pendingAction.id}">Cancel</button>
            </div>
        `;
        return card;
    }

    function createReplyOptions(replyOptions) {
        if (!Array.isArray(replyOptions) || replyOptions.length === 0) {
            return null;
        }
        const exerciseDetailOptions = replyOptions.filter((option) => {
            const workoutId = Number(option?.workout_id);
            return option?.kind === 'exercise_detail' && Number.isFinite(workoutId) && workoutId > 0;
        });
        if (exerciseDetailOptions.length === replyOptions.length) {
            const node = document.createElement('div');
            node.className = 'fitbaseai-reply-options fitbaseai-reply-options--exercise';
            exerciseDetailOptions.forEach((option) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'fitbaseai-reply-option-card';
                button.dataset.fitbaseExerciseDetail = '1';
                button.dataset.workoutId = String(option.workout_id);
                button.dataset.targetUserId = String(option.target_user_id || '');
                button.dataset.targetName = option.target_name || '';
                button.dataset.exerciseName = option.label || '';
                button.dataset.metricLabel = option.metric_label || '';

                const title = document.createElement('div');
                title.className = 'fitbaseai-reply-option-card__title';
                title.textContent = option.label || 'Exercise';

                const meta = document.createElement('div');
                meta.className = 'fitbaseai-reply-option-card__meta';
                meta.textContent = option.metric_label || 'No data yet';

                button.appendChild(title);
                button.appendChild(meta);
                node.appendChild(button);
            });

            const host = document.createElement('div');
            host.className = 'fitbaseai-exercise-detail-host';
            node.appendChild(host);
            return node;
        }
        const node = document.createElement('div');
        node.className = 'fitbaseai-reply-options';
        replyOptions.forEach((option) => {
            const message = String(option?.message || '').trim();
            if (!message) {
                return;
            }
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'fitbaseai-reply-option';
            button.textContent = option.label || message;
            button.dataset.fitbaseReplyMessage = message;
            node.appendChild(button);
        });
        return node.childElementCount ? node : null;
    }

    function formatShortDate(value) {
        if (!value) {
            return '';
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return '';
        }
        return new Intl.DateTimeFormat(undefined, {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        }).format(date);
    }

    function formatNumberLabel(value, unit) {
        const numericValue = Number(value);
        if (!Number.isFinite(numericValue)) {
            return '';
        }
        const rounded = Math.abs(numericValue - Math.round(numericValue)) < 0.01
            ? String(Math.round(numericValue))
            : numericValue.toFixed(1);
        return unit ? `${rounded} ${unit}` : rounded;
    }

    function formatHoldTime(value) {
        const numericValue = Number(value);
        if (!Number.isFinite(numericValue)) {
            return '';
        }
        const totalSeconds = Math.max(0, Math.round(numericValue));
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return `${minutes}:${String(seconds).padStart(2, '0')}`;
    }

    function formatWeightAndReps(weight, reps) {
        const weightLabel = formatNumberLabel(weight, 'lbs');
        const repsNumber = Number(reps);
        const repsLabel = Number.isFinite(repsNumber) ? `${Math.round(repsNumber)} reps` : '';
        if (weightLabel && repsLabel) {
            return `${weightLabel} × ${repsLabel}`;
        }
        return weightLabel || repsLabel || '';
    }

    function formatMetricValue(value, mode) {
        if (mode === 'time_hold') {
            return formatHoldTime(value);
        }
        if (mode === 'cardio') {
            return formatNumberLabel(value, 'min');
        }
        if (mode === 'bodyweight_reps') {
            const numericValue = Number(value);
            return Number.isFinite(numericValue) ? `${Math.round(numericValue)} reps` : '';
        }
        return formatNumberLabel(value, 'lbs');
    }

    function formatMetricSummary(weight, reps, mode) {
        if (mode === 'cardio') {
            const timeLabel = formatMetricValue(reps, mode);
            return timeLabel ? `Bodyweight × ${timeLabel}` : '';
        }
        if (mode === 'time_hold') {
            const holdLabel = formatMetricValue(reps, mode);
            return holdLabel ? `Bodyweight × ${holdLabel}` : '';
        }
        if (mode === 'bodyweight_reps') {
            const repsLabel = formatMetricValue(reps, mode);
            return repsLabel ? `Bodyweight × ${repsLabel}` : '';
        }
        return formatWeightAndReps(weight, reps);
    }

    function createExerciseDetailStat(label, value) {
        if (!value) {
            return null;
        }
        const item = document.createElement('div');
        item.className = 'fitbaseai-exercise-detail__stat';

        const statLabel = document.createElement('div');
        statLabel.className = 'fitbaseai-exercise-detail__stat-label';
        statLabel.textContent = label;

        const statValue = document.createElement('div');
        statValue.className = 'fitbaseai-exercise-detail__stat-value';
        statValue.textContent = value;

        item.appendChild(statLabel);
        item.appendChild(statValue);
        return item;
    }

    function formatChartDateLabel(value) {
        if (!value) {
            return '—';
        }
        const timestamp = Date.parse(value);
        if (Number.isNaN(timestamp)) {
            return '—';
        }
        const date = new Date(timestamp);
        return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }

    function formatChartValue(value, unit, mode) {
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
            return '—';
        }
        if (mode === 'time_hold') {
            return formatHoldTime(numeric);
        }
        if (mode === 'cardio') {
            return formatNumberLabel(numeric, unit || 'min') || '—';
        }
        if (mode === 'bodyweight_reps') {
            return `${Math.round(numeric)} reps`;
        }
        return formatNumberLabel(numeric, unit || 'lbs') || '—';
    }

    function destroyExerciseDetailChart(canvas) {
        if (canvas && canvas._fitbaseChatChart) {
            canvas._fitbaseChatChart.destroy();
            delete canvas._fitbaseChatChart;
        }
    }

    async function hydrateExerciseDetailChart(card, payload) {
        const chartWrapper = card.querySelector('[data-fitbase-detail-chart]');
        const canvas = chartWrapper?.querySelector('canvas');
        const placeholder = chartWrapper?.querySelector('.fitbaseai-exercise-detail__chart-placeholder');
        if (!chartWrapper || !canvas || !placeholder) {
            return;
        }

        const history = Array.isArray(payload?.history) ? payload.history : [];
        const labels = [];
        const values = [];
        history.forEach((entry) => {
            const value = Number(entry?.display_value);
            labels.push(formatChartDateLabel(entry?.recorded_at));
            values.push(Number.isFinite(value) ? Number(value.toFixed(2)) : null);
        });

        const hasValue = values.some((value) => typeof value === 'number');
        if (!hasValue) {
            destroyExerciseDetailChart(canvas);
            chartWrapper.hidden = false;
            placeholder.hidden = false;
            canvas.hidden = true;
            placeholder.textContent = 'Log progress to unlock this chart.';
            revealExpandedExerciseDetail(card);
            return;
        }

        try {
            await ensureChartLibrary();
        } catch (error) {
            console.error('Unable to load chart library', error);
            destroyExerciseDetailChart(canvas);
            chartWrapper.hidden = false;
            placeholder.hidden = false;
            canvas.hidden = true;
            placeholder.textContent = 'Unable to load chart.';
            revealExpandedExerciseDetail(card);
            return;
        }

        const ctx = canvas.getContext('2d');
        destroyExerciseDetailChart(canvas);
        canvas.hidden = false;
        placeholder.hidden = true;

        canvas._fitbaseChatChart = new window.Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        data: values,
                        label: payload?.chart_label || 'Progress',
                        borderColor: DEFAULT_CHART_LINE_COLOR,
                        backgroundColor: DEFAULT_CHART_FILL_COLOR,
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
                            callback: (val) => formatChartValue(val, payload?.chart_unit, payload?.value_mode),
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
                                const lines = [formatChartValue(ctx.parsed.y, payload?.chart_unit, payload?.value_mode)];
                                if (payload?.value_mode === 'strength') {
                                    const weightLine = formatNumberLabel(entry?.weight, 'lbs');
                                    const repsLine = Number.isFinite(Number(entry?.reps)) ? `${Math.round(Number(entry.reps))} reps` : '';
                                    if (weightLine) {
                                        lines.push(`Weight: ${weightLine}`);
                                    }
                                    if (repsLine) {
                                        lines.push(`Reps: ${repsLine}`);
                                    }
                                } else if (payload?.value_mode === 'cardio') {
                                    const timeLine = formatMetricValue(entry?.reps, 'cardio');
                                    if (timeLine) {
                                        lines.push(`Time: ${timeLine}`);
                                    }
                                } else if (payload?.value_mode === 'time_hold') {
                                    const holdLine = formatMetricValue(entry?.reps, 'time_hold');
                                    if (holdLine) {
                                        lines.push(`Hold: ${holdLine}`);
                                    }
                                } else if (payload?.value_mode === 'bodyweight_reps') {
                                    const repsLine = formatMetricValue(entry?.reps, 'bodyweight_reps');
                                    if (repsLine) {
                                        lines.push(`Reps: ${repsLine}`);
                                    }
                                }
                                return lines;
                            },
                        },
                    },
                },
            },
        });
        revealExpandedExerciseDetail(card);
    }

    function buildExerciseProgressSummary(payload) {
        const summary = payload?.summary || {};
        const valueMode = payload?.value_mode || 'strength';
        const firstValue = valueMode === 'strength' ? (summary?.first_one_rm ?? summary?.first_value) : summary?.first_value;
        const latestValue = valueMode === 'strength' ? (summary?.latest_one_rm ?? summary?.latest_value) : summary?.latest_value;
        const firstLabel = formatMetricValue(firstValue, valueMode);
        const latestLabel = formatMetricValue(latestValue, valueMode);
        if (firstLabel && latestLabel && firstLabel !== latestLabel) {
            return `Progressed from ${firstLabel} to ${latestLabel}.`;
        }
        const bestLabel = formatMetricValue(summary?.best_value, valueMode);
        if (bestLabel) {
            return `Best recorded value: ${bestLabel}.`;
        }
        return '';
    }

    function createExerciseDetailCard(payload, sourceButton) {
        const workout = payload?.workout || {};
        const summary = payload?.summary || {};
        const valueMode = payload?.value_mode || 'strength';
        const card = document.createElement('div');
        card.className = 'fitbaseai-exercise-detail';

        const stats = document.createElement('div');
        stats.className = 'fitbaseai-exercise-detail__stats';
        const statNodes = [
            createExerciseDetailStat('Started with', formatMetricSummary(summary.first_weight, summary.first_reps, valueMode)),
            createExerciseDetailStat('Latest logged max', formatMetricSummary(workout.max_weight, workout.max_reps, valueMode)),
            createExerciseDetailStat('First recorded', formatShortDate(summary.first_recorded_at)),
            createExerciseDetailStat('Last updated', formatShortDate(workout.updated_at || summary.latest_recorded_at)),
        ].filter(Boolean);
        statNodes.forEach((node) => stats.appendChild(node));
        if (statNodes.length) {
            card.appendChild(stats);
        }

        const progressSummary = buildExerciseProgressSummary(payload);
        if (progressSummary) {
            const summaryBlock = document.createElement('div');
            summaryBlock.className = 'fitbaseai-exercise-detail__summary';
            summaryBlock.textContent = progressSummary;
            card.appendChild(summaryBlock);
        }

        const notes = String(workout.notes || '').trim();
        if (notes) {
            const notesBlock = document.createElement('div');
            notesBlock.className = 'fitbaseai-exercise-detail__notes';
            const notesLabel = document.createElement('div');
            notesLabel.className = 'fitbaseai-exercise-detail__notes-label';
            notesLabel.textContent = 'Notes';
            const notesBody = document.createElement('div');
            notesBody.className = 'fitbaseai-exercise-detail__notes-body';
            notesBody.textContent = notes;
            notesBlock.appendChild(notesLabel);
            notesBlock.appendChild(notesBody);
            card.appendChild(notesBlock);
        }

        const chart = document.createElement('div');
        chart.className = 'fitbaseai-exercise-detail__chart';
        chart.dataset.fitbaseDetailChart = '1';

        const chartLabel = document.createElement('div');
        chartLabel.className = 'fitbaseai-exercise-detail__chart-label';
        chartLabel.textContent = payload?.chart_label || 'Estimated 1RM (lbs)';
        chart.appendChild(chartLabel);

        const plot = document.createElement('div');
        plot.className = 'fitbaseai-exercise-detail__chart-plot';

        const canvas = document.createElement('canvas');
        canvas.className = 'fitbaseai-exercise-detail__chart-canvas';
        canvas.setAttribute('aria-label', 'Exercise history chart');
        canvas.hidden = true;
        plot.appendChild(canvas);

        const placeholder = document.createElement('div');
        placeholder.className = 'fitbaseai-exercise-detail__chart-placeholder';
        placeholder.textContent = 'Loading chart…';
        plot.appendChild(placeholder);

        chart.appendChild(plot);
        card.appendChild(chart);

        return card;
    }

    function createExerciseDetailLoadingCard() {
        const card = document.createElement('div');
        card.className = 'fitbaseai-exercise-detail fitbaseai-exercise-detail--loading';
        card.textContent = 'Loading exercise details…';
        return card;
    }

    function createExerciseDetailErrorCard(message) {
        const card = document.createElement('div');
        card.className = 'fitbaseai-exercise-detail fitbaseai-exercise-detail--error';
        card.textContent = message || 'Unable to load exercise details.';
        return card;
    }

    function revealExpandedExerciseDetail(node) {
        if (!node || !messagesRoot) {
            return;
        }
        requestAnimationFrame(() => {
            const nodeBottom = node.offsetTop + node.offsetHeight;
            const visibleBottom = messagesRoot.scrollTop + messagesRoot.clientHeight;
            if (nodeBottom > visibleBottom - 16) {
                messagesRoot.scrollTo({
                    top: Math.max(0, nodeBottom - messagesRoot.clientHeight + 20),
                    behavior: 'smooth'
                });
            }
        });
    }

    async function expandExerciseDetail(button) {
        if (!config.exerciseHistoryUrl) {
            return;
        }
        const optionsRoot = button.closest('.fitbaseai-reply-options--exercise');
        const detailHost = optionsRoot?.querySelector('.fitbaseai-exercise-detail-host');
        if (!optionsRoot || !detailHost) {
            return;
        }

        optionsRoot.querySelectorAll('.fitbaseai-reply-option-card').forEach((optionButton) => {
            optionButton.classList.toggle('is-active', optionButton === button);
        });

        const cachedPayload = button._exerciseDetailPayload;
        if (cachedPayload) {
            const card = createExerciseDetailCard(cachedPayload, button);
            detailHost.replaceChildren(card);
            revealExpandedExerciseDetail(card);
            void hydrateExerciseDetailChart(card, cachedPayload);
            return;
        }

        const loadingCard = createExerciseDetailLoadingCard();
        detailHost.replaceChildren(loadingCard);
        revealExpandedExerciseDetail(loadingCard);
        try {
            const url = new URL(config.exerciseHistoryUrl, window.location.origin);
            url.searchParams.set('workout_id', button.dataset.workoutId);
            url.searchParams.set('window', 'all');
            const targetUserId = Number(button.dataset.targetUserId);
            if (Number.isFinite(targetUserId) && targetUserId > 0 && targetUserId !== Number(config.userId)) {
                url.searchParams.set('target_user_id', String(targetUserId));
            }

            const response = await fetch(url.toString(), {
                credentials: 'same-origin'
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                const errorCard = createExerciseDetailErrorCard(payload.error || 'Unable to load exercise details.');
                detailHost.replaceChildren(errorCard);
                revealExpandedExerciseDetail(errorCard);
                return;
            }

            button._exerciseDetailPayload = payload;
            const card = createExerciseDetailCard(payload, button);
            detailHost.replaceChildren(card);
            revealExpandedExerciseDetail(card);
            void hydrateExerciseDetailChart(card, payload);
        } catch (error) {
            console.error('Unable to load exercise detail', error);
            const errorCard = createExerciseDetailErrorCard('Unable to load exercise details.');
            detailHost.replaceChildren(errorCard);
            revealExpandedExerciseDetail(errorCard);
        }
    }

    function buildActionStateElement(state) {
        const tone = state === 'cancelled' ? 'cancelled' : 'completed';
        const node = document.createElement('div');
        node.className = `fitbaseai-action-card__state fitbaseai-action-card__state--${tone}`;
        if (tone === 'cancelled') {
            node.innerHTML = '<i class="bi bi-slash-circle-fill"></i><span>Cancelled</span>';
        } else {
            node.innerHTML = '<i class="bi bi-check-circle-fill"></i><span>Completed</span>';
        }
        return node;
    }

    function resolveActionCardInPlace(actionId, state, finalMessage) {
        const card = messagesRoot.querySelector(`.fitbaseai-action-card[data-action-id="${actionId}"]`);
        if (!card) {
            return null;
        }
        const article = card.closest('.fitbaseai-message');
        card.classList.add('is-resolved');
        card.classList.remove('fitbaseai-action-card--completed', 'fitbaseai-action-card--cancelled');
        card.classList.add(state === 'cancelled' ? 'fitbaseai-action-card--cancelled' : 'fitbaseai-action-card--completed');

        const buttons = card.querySelector('.fitbaseai-action-card__buttons');
        if (buttons) {
            buttons.remove();
        }

        let stateNode = card.querySelector('.fitbaseai-action-card__state');
        if (!stateNode) {
            stateNode = buildActionStateElement(state);
            card.insertBefore(stateNode, card.firstChild);
        } else {
            stateNode.replaceWith(buildActionStateElement(state));
        }

        const summary = card.querySelector('.fitbaseai-action-card__summary');
        if (summary && finalMessage) {
            summary.textContent = finalMessage;
        }

        if (article) {
            article.classList.add('fitbaseai-message--action-only');
            article.classList.remove('fitbaseai-message--success', 'fitbaseai-message--cancelled');
        }

        messagesRoot.scrollTop = messagesRoot.scrollHeight;
        return article || card;
    }

    function renderMessage(role, content, metadata) {
        clearDefaultMessage();
        const meta = metadata || {};
        const messageText = (content || '').trim();
        const pendingAction = meta.pending_action || null;
        const pendingActions = Array.isArray(meta.pending_actions) ? meta.pending_actions.filter(Boolean) : [];
        if (pendingAction && !pendingActions.length) {
            pendingActions.push(pendingAction);
        }
        const replyOptions = meta.reply_options || meta.tool_result?.reply_options || [];
        const completionState = meta.completion_state
            || (meta.action_status === 'cancelled' ? 'cancelled' : '')
            || (meta.action_result && meta.action_result.success ? 'success' : '');
        if (role !== 'user' && meta.action_id && completionState) {
            const resolved = resolveActionCardInPlace(
                meta.action_id,
                completionState === 'cancelled' ? 'cancelled' : 'completed',
                messageText
            );
            if (resolved) {
                return resolved;
            }
        }
        const actionOnly = role !== 'user' && pendingActions.length > 0 && !messageText;
        const article = document.createElement('article');
        article.className = `fitbaseai-message fitbaseai-message--${role === 'user' ? 'user' : 'assistant'}`;
        if (actionOnly) {
            article.classList.add('fitbaseai-message--action-only');
        }
        if (completionState) {
            article.classList.add(`fitbaseai-message--${completionState}`);
        }
        article.dataset.seed = 'persisted';

        if (!actionOnly) {
            const label = document.createElement('div');
            label.className = 'fitbaseai-message__label';
            label.textContent = role === 'user' ? 'You' : 'FitBaseAI';
            article.appendChild(label);
        }

        if (completionState && role !== 'user') {
            const state = document.createElement('div');
            state.className = `fitbaseai-message__state fitbaseai-message__state--${completionState}`;
            if (completionState === 'success') {
                state.innerHTML = '<i class="bi bi-check-circle-fill"></i><span>Completed</span>';
            } else if (completionState === 'cancelled') {
                state.innerHTML = '<i class="bi bi-slash-circle-fill"></i><span>Cancelled</span>';
            }
            article.appendChild(state);
        }

        if (messageText) {
            const body = document.createElement('div');
            body.className = 'fitbaseai-message__body';
            body.textContent = messageText;
            article.appendChild(body);
        }

        const citations = createCitationList(meta.citations);
        if (citations) {
            article.appendChild(citations);
        }

        const replyOptionsNode = createReplyOptions(replyOptions);
        if (replyOptionsNode) {
            article.appendChild(replyOptionsNode);
        }

        pendingActions.forEach((action) => {
            const actionCard = createPendingActionCard(action);
            if (actionCard) {
                article.appendChild(actionCard);
            }
        });

        messagesRoot.appendChild(article);
        messagesRoot.scrollTop = messagesRoot.scrollHeight;
        return article;
    }

    async function loadLatestThread() {
        if (!config.latestThreadUrl) {
            threadLoaded = true;
            return false;
        }
        try {
            const response = await fetch(config.latestThreadUrl, {
                credentials: 'same-origin'
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                return false;
            }
            currentThreadId = payload.thread_id || null;
            if (currentThreadId) {
                window.localStorage.setItem(threadStorageKey, currentThreadId);
            } else {
                window.localStorage.removeItem(threadStorageKey);
            }
            const messages = Array.isArray(payload.messages) ? payload.messages : [];
            if (messages.length) {
                messagesRoot.innerHTML = '';
                messages.forEach((message) => {
                    renderMessage(message.role, message.content, message.metadata || {});
                });
            }
            threadLoaded = true;
            return Boolean(currentThreadId);
        } catch (error) {
            console.error('Unable to load latest FitBaseAI thread', error);
            return false;
        }
    }

    async function loadThread() {
        if (!currentThreadId) {
            return false;
        }
        try {
            const response = await fetch(buildUrl(config.threadUrlTemplate, currentThreadId), {
                credentials: 'same-origin'
            });
            const payload = await response.json();
            const messages = Array.isArray(payload.messages) ? payload.messages : [];
            if (!response.ok || !payload.success || messages.length === 0) {
                window.localStorage.removeItem(threadStorageKey);
                currentThreadId = null;
                threadLoaded = false;
                return false;
            }
            messagesRoot.innerHTML = '';
            messages.forEach((message) => {
                renderMessage(message.role, message.content, message.metadata || {});
            });
            threadLoaded = true;
            return true;
        } catch (error) {
            console.error('Unable to load FitBaseAI thread', error);
            return false;
        }
    }

    async function syncThreadOnOpen() {
        if (threadLoadPromise) {
            await threadLoadPromise;
            return;
        }
        threadLoadPromise = (async () => {
            const fallbackThreadId = currentThreadId;
            const loadedLatest = await loadLatestThread();
            if (!loadedLatest && !threadLoaded && fallbackThreadId) {
                currentThreadId = fallbackThreadId;
                await loadThread();
            }
        })();
        try {
            await threadLoadPromise;
        } finally {
            threadLoadPromise = null;
        }
    }

    function persistShellOpenState(isOpen) {
        if (isOpen) {
            window.localStorage.setItem(openStateStorageKey, '1');
        } else {
            window.localStorage.removeItem(openStateStorageKey);
        }
    }

    function openShell(options) {
        const shouldFocus = options?.focus !== false;
        shell.hidden = false;
        shell.setAttribute('aria-hidden', 'false');
        document.body.classList.add('fitbaseai-open');
        setPanelModalState();
        restoreStoredPanelWidth();
        persistShellOpenState(true);
        scheduleViewportSync();
        if (shouldFocus) {
            focusInput();
        }
        void syncThreadOnOpen();
    }

    function closeShell() {
        shell.hidden = true;
        shell.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('fitbaseai-open');
        document.body.classList.remove('fitbaseai-resizing');
        activeResizePointerId = null;
        persistShellOpenState(false);
        clearViewportSyncState();
    }

    function setSendingState(isSending) {
        sending = isSending;
        sendButton.disabled = isSending;
        input.disabled = isSending;
        if (clearHistoryButton) {
            clearHistoryButton.disabled = isSending || clearingHistory;
        }
    }

    function setClearingHistoryState(isClearing) {
        clearingHistory = isClearing;
        if (clearHistoryButton) {
            clearHistoryButton.disabled = isClearing || sending;
        }
        if (isClearing) {
            input.disabled = true;
            sendButton.disabled = true;
        } else if (!sending) {
            input.disabled = false;
            sendButton.disabled = false;
        }
    }

    async function clearHistory() {
        if (!config.clearHistoryUrl || clearingHistory || sending) {
            return;
        }
        const confirmed = window.confirm('Clear your FitBaseAI chat history on this account? This will remove the conversation across your devices.');
        if (!confirmed) {
            return;
        }

        setClearingHistoryState(true);
        setStatus('Clearing FitBaseAI history…', 'info');

        try {
            const response = await fetch(config.clearHistoryUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                setStatus(payload.error || 'Unable to clear your FitBaseAI history.', 'danger');
                return;
            }

            currentThreadId = null;
            threadLoaded = true;
            threadLoadPromise = null;
            window.localStorage.removeItem(threadStorageKey);
            resetMessagesToDefault();
            setStatus('FitBaseAI history cleared.', 'success');
            focusInput();
        } catch (error) {
            console.error('Unable to clear FitBaseAI history', error);
            setStatus('Unable to clear your FitBaseAI history.', 'danger');
        } finally {
            setClearingHistoryState(false);
        }
    }

    async function sendMessage(rawText) {
        const message = (rawText || '').trim();
        if (!message || sending) {
            return;
        }

        renderMessage('user', message, {});
        setStatus('FitBaseAI is thinking…', 'info');
        input.value = '';
        setSendingState(true);

        try {
            const response = await fetch(config.chatUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    thread_id: currentThreadId,
                    message,
                    page_context: buildPageContext()
                })
            });
            const payload = await response.json();
            if (!payload.success) {
                setStatus(payload.error || 'FitBaseAI could not complete that request.', 'danger');
                renderMessage('assistant', payload.error || 'FitBaseAI could not complete that request.', {});
                return;
            }

            currentThreadId = payload.thread_id || currentThreadId;
            if (currentThreadId) {
                window.localStorage.setItem(threadStorageKey, currentThreadId);
                threadLoaded = true;
            }
            renderMessage('assistant', payload.message, {
                citations: payload.citations || [],
                pending_action: payload.pending_action || null,
                pending_actions: payload.pending_actions || [],
                tool_result: payload.tool_result || null,
                reply_options: payload.tool_result?.reply_options || []
            });
            const budget = payload.budget || {};
            if (budget.blocked) {
                setStatus('FitBaseAI hit the current monthly budget stop.', 'warning');
            } else {
                setStatus('', '');
            }
        } catch (error) {
            console.error('FitBaseAI request failed', error);
            setStatus('FitBaseAI hit a temporary issue.', 'danger');
            renderMessage('assistant', 'FitBaseAI hit a temporary issue.', {});
        } finally {
            setSendingState(false);
            focusInput();
        }
    }

    async function resolveAction(actionId, mode) {
        const buttonSelector = mode === 'confirm' ? `[data-fitbase-action-confirm="${actionId}"]` : `[data-fitbase-action-cancel="${actionId}"]`;
        const button = messagesRoot.querySelector(buttonSelector);
        if (!button) {
            return;
        }
        button.disabled = true;
        const url = mode === 'confirm'
            ? buildUrl(config.confirmUrlTemplate, actionId)
            : buildUrl(config.cancelUrlTemplate, actionId);

        try {
            const response = await fetch(url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const payload = await response.json();
            if (!payload.success) {
                const failureMessage = payload.error || payload.message || payload.result?.error || 'That FitBaseAI action could not be completed.';
                setStatus(failureMessage, 'danger');
                button.disabled = false;
                return;
            }
            const completionMetadata = {
                action_id: actionId,
                action_result: payload.result || null,
                action_status: mode === 'confirm' ? 'completed' : 'cancelled',
                completion_state: mode === 'confirm' ? 'success' : 'cancelled'
            };
            const resolved = resolveActionCardInPlace(
                actionId,
                mode === 'confirm' ? 'completed' : 'cancelled',
                payload.message
            );
            if (!resolved) {
                renderMessage('assistant', payload.message, completionMetadata);
            }
            const card = button.closest('.fitbaseai-action-card');
            if (card) {
                card.classList.add('is-resolved');
            }
            if (mode === 'confirm' && payload.result && payload.result.action_type) {
                window.dispatchEvent(new CustomEvent('fitbaseai:action-completed', {
                    detail: payload.result
                }));
            }
            setStatus('', '');
        } catch (error) {
            console.error('FitBaseAI action failed', error);
            setStatus('That FitBaseAI action could not be completed.', 'danger');
            button.disabled = false;
        }
    }

    async function submitAdminForm(formElement, url, useFormData) {
        if (!formElement || !url) {
            return;
        }
        const options = {
            method: 'POST',
            credentials: 'same-origin'
        };
        if (useFormData) {
            options.body = new FormData(formElement);
        } else {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify({});
        }
        if (adminStatus) {
            adminStatus.textContent = 'Working…';
            adminStatus.dataset.tone = 'info';
        }
        try {
            const response = await fetch(url, options);
            const payload = await response.json();
            if (!payload.success) {
                if (adminStatus) {
                    adminStatus.textContent = payload.error || 'That FitBaseAI admin action failed.';
                    adminStatus.dataset.tone = 'danger';
                }
                return;
            }
            if (adminStatus) {
                adminStatus.textContent = useFormData
                    ? 'Manuscript content uploaded to FitBaseAI.'
                    : 'FitBaseAI research sync completed.';
                adminStatus.dataset.tone = 'success';
            }
        } catch (error) {
            console.error('FitBaseAI admin action failed', error);
            if (adminStatus) {
                adminStatus.textContent = 'That FitBaseAI admin action failed.';
                adminStatus.dataset.tone = 'danger';
            }
        }
    }

    document.querySelectorAll('[data-fitbase-launcher]').forEach((launcher) => {
        launcher.addEventListener('click', () => openShell());
    });

    document.querySelectorAll('[data-fitbase-close]').forEach((closer) => {
        closer.addEventListener('click', () => closeShell());
    });

    if (clearHistoryButton) {
        clearHistoryButton.addEventListener('click', () => {
            clearHistory();
        });
    }

    shell.addEventListener('click', (event) => {
        const confirmId = event.target.closest('[data-fitbase-action-confirm]')?.dataset.fitbaseActionConfirm;
        if (confirmId) {
            resolveAction(confirmId, 'confirm');
            return;
        }
        const cancelId = event.target.closest('[data-fitbase-action-cancel]')?.dataset.fitbaseActionCancel;
        if (cancelId) {
            resolveAction(cancelId, 'cancel');
            return;
        }
        const exerciseDetailButton = event.target.closest('[data-fitbase-exercise-detail]');
        if (exerciseDetailButton) {
            expandExerciseDetail(exerciseDetailButton);
            return;
        }
        const replyMessage = event.target.closest('[data-fitbase-reply-message]')?.dataset.fitbaseReplyMessage;
        if (replyMessage) {
            sendMessage(replyMessage);
        }
    });

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        sendMessage(input.value);
    });

    input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            sendMessage(input.value);
        }
    });

    input.addEventListener('focus', () => {
        scheduleViewportSync({ keepComposerVisible: true });
    });

    input.addEventListener('click', () => {
        scheduleViewportSync({ keepComposerVisible: true });
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !shell.hidden) {
            closeShell();
        }
    });

    const manuscriptForm = document.querySelector('[data-fitbase-manuscript-form]');
    if (manuscriptForm && config.manuscriptUploadUrl) {
        manuscriptForm.addEventListener('submit', (event) => {
            event.preventDefault();
            submitAdminForm(manuscriptForm, config.manuscriptUploadUrl, true);
        });
    }

    const researchSyncForm = document.querySelector('[data-fitbase-research-sync-form]');
    if (researchSyncForm && config.researchSyncUrl) {
        researchSyncForm.addEventListener('submit', (event) => {
            event.preventDefault();
            submitAdminForm(researchSyncForm, config.researchSyncUrl, false);
        });
    }

    function beginPanelResize(event) {
        if (!resizeHandle || !isDesktopPanelMode()) {
            return;
        }
        activeResizePointerId = event.pointerId;
        resizeHandle.setPointerCapture(event.pointerId);
        document.body.classList.add('fitbaseai-resizing');
        event.preventDefault();
    }

    function updatePanelResize(clientX) {
        if (activeResizePointerId === null || !isDesktopPanelMode()) {
            return;
        }
        const appliedWidth = applyPanelWidth(window.innerWidth - clientX);
        if (appliedWidth) {
            window.localStorage.setItem(panelWidthStorageKey, String(Math.round(appliedWidth)));
        }
    }

    function endPanelResize(event) {
        if (activeResizePointerId === null) {
            return;
        }
        if (resizeHandle && event && resizeHandle.hasPointerCapture?.(event.pointerId)) {
            resizeHandle.releasePointerCapture(event.pointerId);
        }
        activeResizePointerId = null;
        document.body.classList.remove('fitbaseai-resizing');
    }

    if (resizeHandle) {
        resizeHandle.addEventListener('pointerdown', beginPanelResize);
        resizeHandle.addEventListener('pointermove', (event) => {
            if (event.pointerId !== activeResizePointerId) {
                return;
            }
            updatePanelResize(event.clientX);
        });
        resizeHandle.addEventListener('pointerup', endPanelResize);
        resizeHandle.addEventListener('pointercancel', endPanelResize);
    }

    window.addEventListener('pointermove', (event) => {
        if (event.pointerId !== activeResizePointerId) {
            return;
        }
        updatePanelResize(event.clientX);
    });
    window.addEventListener('pointerup', endPanelResize);
    window.addEventListener('pointercancel', endPanelResize);
    window.addEventListener('resize', () => {
        setPanelModalState();
        if (isDesktopPanelMode()) {
            restoreStoredPanelWidth();
        } else {
            panel.style.removeProperty('--fitbaseai-panel-width');
        }
        scheduleViewportSync({
            keepComposerVisible: document.activeElement === input
        });
    });

    if (window.visualViewport) {
        const syncViewportWithKeyboard = () => {
            scheduleViewportSync({
                keepComposerVisible: document.activeElement === input
            });
        };
        window.visualViewport.addEventListener('resize', syncViewportWithKeyboard);
        window.visualViewport.addEventListener('scroll', syncViewportWithKeyboard);
    }

    setPanelModalState();
    if (isDesktopPanelMode()) {
        restoreStoredPanelWidth();
    }

    if (window.localStorage.getItem(openStateStorageKey) === '1') {
        openShell({ focus: false });
    }
})();
