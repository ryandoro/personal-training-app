(function () {
    class ExercisePickerModal {
        constructor(root) {
            this.root = root;
            this.wheel = root?.querySelector('[data-role="picker-wheel"]') || null;
            this.listNode = root?.querySelector('[data-role="picker-list"]') || null;
            this.loadingNode = root?.querySelector('[data-role="picker-loading"]') || null;
            this.errorNode = root?.querySelector('[data-role="picker-error"]') || null;
            this.errorTextNode = root?.querySelector('[data-role="picker-error-text"]') || null;
            this.emptyNode = root?.querySelector('[data-role="picker-empty"]') || null;
            this.highlightNode = root?.querySelector('.exercise-picker-highlight') || null;
            this.subcategoryNode = root?.querySelector('[data-role="picker-subcategory"]') || null;
            this.selectionLabel = root?.querySelector('[data-role="picker-selection-label"]') || null;
            this.confirmBtn = root?.querySelector('[data-role="picker-confirm"]') || null;
            this.cancelBtn = root?.querySelector('[data-role="picker-cancel"]') || null;
            this.retryBtn = root?.querySelector('[data-role="picker-retry"]') || null;
            this.closeButtons = Array.from(root?.querySelectorAll('[data-role="picker-close"]') || []);
            this.activeFetcher = null;
            this.pendingRequestToken = null;
            this.options = [];
            this.selectedIndex = -1;
            this.confirmDefaultText = this.confirmBtn ? this.confirmBtn.textContent : '';

            if (!root) {
                return;
            }

            this.handleWheelScroll = this.handleWheelScroll.bind(this);
            this.handleKeydown = this.handleKeydown.bind(this);

            this.bindEvents();
        }

        bindEvents() {
            if (this.wheel) {
                this.wheel.addEventListener('scroll', this.handleWheelScroll, { passive: true });
            }
            if (this.listNode) {
                this.listNode.addEventListener('click', (event) => {
                    const optionBtn = event.target.closest('[data-role="picker-option"]');
                    if (!optionBtn) return;
                    const index = parseInt(optionBtn.dataset.index || '', 10);
                    if (Number.isInteger(index)) {
                        event.preventDefault();
                        this.selectIndex(index);
                    }
                });
            }
            this.closeButtons.forEach((btn) => {
                btn.addEventListener('click', (event) => {
                    event.preventDefault();
                    this.close();
                });
            });
            if (this.cancelBtn) {
                this.cancelBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    this.close();
                });
            }
            if (this.retryBtn) {
                this.retryBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    this.fetchOptions();
                });
            }
            if (this.confirmBtn) {
                this.confirmBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    this.confirmSelection();
                });
            }
            if (this.root) {
                this.root.addEventListener('click', (event) => {
                    if (event.target === this.root) {
                        this.close();
                    }
                });
            }
            document.addEventListener('keydown', this.handleKeydown);
        }

        handleKeydown(event) {
            if (!this.isOpen()) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                this.close();
            } else if (event.key === 'Enter' && document.activeElement === this.root) {
                event.preventDefault();
                this.confirmSelection();
            }
        }

        handleWheelScroll() {
            if (!this.highlightNode || !this.listNode) return;
            const options = Array.from(this.listNode.querySelectorAll('[data-role="picker-option"]'));
            if (!options.length) return;
            const highlightRect = this.highlightNode.getBoundingClientRect();
            let closestIndex = this.selectedIndex;
            let smallestDelta = Number.POSITIVE_INFINITY;
            options.forEach((optionBtn) => {
                const rect = optionBtn.getBoundingClientRect();
                const center = rect.top + rect.height / 2;
                const delta = Math.abs(center - (highlightRect.top + highlightRect.height / 2));
                if (delta < smallestDelta) {
                    smallestDelta = delta;
                    closestIndex = parseInt(optionBtn.dataset.index || '', 10);
                }
            });
            if (Number.isInteger(closestIndex) && closestIndex !== this.selectedIndex) {
                this.selectIndex(closestIndex, { ensureVisible: false });
            }
        }

        isOpen() {
            return !!this.root && this.root.classList.contains('is-visible');
        }

        open({ subcategory = '', fetchOptions = null, onSelect = null } = {}) {
            if (!this.root) return;
            this.activeFetcher = typeof fetchOptions === 'function' ? fetchOptions : null;
            this.onConfirm = typeof onSelect === 'function' ? onSelect : null;
            this.subcategoryNode && (this.subcategoryNode.textContent = subcategory || 'this workout');
            this.selectionLabel && (this.selectionLabel.textContent = 'Pick an exercise to continue.');
            this.selectedIndex = -1;
            this.options = [];
            this.setConfirmLoading(false);
            if (this.confirmBtn) {
                this.confirmBtn.disabled = true;
            }
            if (this.listNode) {
                this.listNode.innerHTML = '';
            }
            this.showLoadingState();
            this.root.classList.add('is-visible');
            document.body.classList.add('exercise-picker-open');
            this.fetchOptions();
        }

        fetchOptions() {
            if (!this.activeFetcher) {
                this.showError('Unable to load exercises.');
                return;
            }
            this.showLoadingState();
            const requestToken = Symbol('picker-request');
            this.pendingRequestToken = requestToken;
            Promise.resolve()
                .then(() => this.activeFetcher())
                .then((options) => {
                    if (this.pendingRequestToken !== requestToken) return;
                    this.renderOptions(Array.isArray(options) ? options : []);
                })
                .catch((error) => {
                    if (this.pendingRequestToken !== requestToken) return;
                    const message = error?.message || 'Unable to load exercises.';
                    this.showError(message);
                });
        }

        renderOptions(options) {
            this.pendingRequestToken = null;
            if (!this.listNode) return;
            this.listNode.innerHTML = '';
            const sortedOptions = Array.isArray(options)
                ? [...options].sort((a, b) => {
                    const nameA = String(a?.name || '').trim().toLowerCase();
                    const nameB = String(b?.name || '').trim().toLowerCase();
                    if (nameA === nameB) return 0;
                    return nameA < nameB ? -1 : 1;
                })
                : [];
            this.options = sortedOptions;
            if (!sortedOptions.length) {
                this.showEmptyState();
                return;
            }
            sortedOptions.forEach((option, index) => {
                const li = document.createElement('li');
                li.className = 'exercise-picker-item';
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'exercise-picker-option';
                button.setAttribute('data-role', 'picker-option');
                button.dataset.index = String(index);

                const name = document.createElement('span');
                name.className = 'exercise-picker-option__name';
                name.textContent = option?.name || 'Exercise';

                button.appendChild(name);
                li.appendChild(button);
                this.listNode.appendChild(li);
            });
            this.showListState();
            requestAnimationFrame(() => {
                this.selectIndex(0, { ensureVisible: true, silent: true });
            });
        }

        showLoadingState() {
            this.toggleState('loading');
        }

        showEmptyState() {
            this.toggleState('empty');
        }

        showError(message) {
            if (this.errorTextNode) {
                this.errorTextNode.textContent = message;
            }
            this.toggleState('error');
        }

        showListState() {
            this.toggleState('list');
        }

        toggleState(state) {
            if (this.loadingNode) this.loadingNode.hidden = state !== 'loading';
            if (this.emptyNode) this.emptyNode.hidden = state !== 'empty';
            if (this.errorNode) this.errorNode.hidden = state !== 'error';
            if (this.listNode) this.listNode.hidden = state !== 'list';
        }

        selectIndex(index, { ensureVisible = true, silent = false } = {}) {
            if (!Array.isArray(this.options) || !this.listNode) return;
            if (index < 0 || index >= this.options.length) {
                return;
            }
            this.selectedIndex = index;
            const buttons = this.listNode.querySelectorAll('[data-role="picker-option"]');
            buttons.forEach((btn) => {
                btn.classList.toggle('is-selected', parseInt(btn.dataset.index || '', 10) === index);
            });
            if (ensureVisible) {
                const active = this.listNode.querySelector(`[data-role="picker-option"][data-index="${index}"]`);
                if (active && this.wheel) {
                    const wheelRect = this.wheel.getBoundingClientRect();
                    const activeRect = active.getBoundingClientRect();
                    const targetScroll = active.offsetTop - (wheelRect.height / 2 - activeRect.height / 2);
                    this.wheel.scrollTo({ top: targetScroll, behavior: 'smooth' });
                }
            }
            if (!silent && this.selectionLabel) {
                const option = this.options[index];
                const name = option?.name || 'Exercise';
                this.selectionLabel.textContent = `${name} selected.`;
            }
            if (this.confirmBtn) {
                this.confirmBtn.disabled = false;
            }
        }

        setConfirmLoading(isLoading) {
            if (!this.confirmBtn) return;
            if (isLoading) {
                this.confirmBtn.disabled = true;
                this.confirmBtn.dataset.loading = 'true';
                this.confirmBtn.textContent = 'Updating…';
            } else {
                this.confirmBtn.dataset.loading = 'false';
                this.confirmBtn.textContent = this.confirmDefaultText || 'Use Exercise';
                this.confirmBtn.disabled = this.selectedIndex < 0;
            }
        }

        confirmSelection() {
            if (this.selectedIndex < 0 || typeof this.onConfirm !== 'function') {
                return;
            }
            const option = this.options[this.selectedIndex];
            this.setConfirmLoading(true);
            let closeOnResolve = true;
            Promise.resolve()
                .then(() => this.onConfirm(option))
                .then((shouldClose) => {
                    closeOnResolve = shouldClose !== false;
                })
                .catch((error) => {
                    const message = error?.message || 'Unable to update exercise.';
                    if (this.selectionLabel) {
                        this.selectionLabel.textContent = message;
                        this.selectionLabel.classList.add('text-danger');
                        setTimeout(() => {
                            if (!this.selectionLabel) return;
                            this.selectionLabel.classList.remove('text-danger');
                            if (this.isOpen()) {
                                this.selectionLabel.textContent = 'Pick an exercise to continue.';
                            }
                        }, 2500);
                    }
                    closeOnResolve = false;
                })
                .finally(() => {
                    this.setConfirmLoading(false);
                    if (closeOnResolve) {
                        this.close();
                    }
                });
        }

        close() {
            this.pendingRequestToken = null;
            this.activeFetcher = null;
            this.onConfirm = null;
            if (this.root) {
                this.root.classList.remove('is-visible');
            }
            document.body.classList.remove('exercise-picker-open');
        }
    }

    window.ExercisePickerModal = ExercisePickerModal;
})();
