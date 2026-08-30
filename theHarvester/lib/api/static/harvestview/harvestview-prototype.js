'use strict';

// Throwaway prototype: three visual territories and one staged enumeration planner,
// switchable on the existing routes with ?variant=mineral|ledger|signal.
(() => {
  const variants = [
    ['mineral', 'Mineral Run Desk'],
    ['ledger', 'Field Evidence Ledger'],
    ['signal', 'Signal Bay'],
  ];
  const params = new URLSearchParams(location.search);
  const initialVariant = params.get('variant');
  if (!variants.some(([key]) => key === initialVariant)) return;

  const root = document.documentElement;
  const state = {variant: initialVariant, plannerStep: null};
  root.dataset.prototypeVariant = initialVariant;
  document.body.classList.add('harvestview-prototype');

  const switcher = document.createElement('aside');
  switcher.className = 'prototype-switcher';
  switcher.setAttribute('aria-label', 'HarvestView prototype controls');
  switcher.innerHTML = `
    <button type="button" data-prototype-direction="-1" aria-label="Previous visual territory">←</button>
    <output id="prototype-variant-label"></output>
    <button type="button" data-prototype-direction="1" aria-label="Next visual territory">→</button>
    <label>Color mode
      <select id="prototype-color-mode">
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
    <small id="prototype-state"></small>`;
  document.body.append(switcher);

  const variantLabel = switcher.querySelector('#prototype-variant-label');
  const prototypeState = switcher.querySelector('#prototype-state');
  const colorMode = switcher.querySelector('#prototype-color-mode');

  function renderPrototypeState() {
    const name = variants.find(([key]) => key === state.variant)[1];
    variantLabel.textContent = name;
    prototypeState.textContent = `Prototype · ${location.pathname}${state.plannerStep ? ` · Planner ${state.plannerStep}/4` : ''}`;
  }

  function setVariant(key) {
    state.variant = key;
    root.dataset.prototypeVariant = key;
    const nextParams = new URLSearchParams(location.search);
    nextParams.set('variant', key);
    history.replaceState(null, '', `${location.pathname}?${nextParams}${location.hash}`);
    for (const link of document.querySelectorAll('a[href]')) {
      const target = new URL(link.href);
      if (!['/', '/schedules'].includes(target.pathname) || target.origin !== location.origin) continue;
      target.searchParams.set('variant', key);
      link.href = `${target.pathname}?${target.searchParams}`;
    }
    renderPrototypeState();
  }

  function cycleVariant(direction) {
    const current = variants.findIndex(([key]) => key === state.variant);
    setVariant(variants[(current + direction + variants.length) % variants.length][0]);
  }

  switcher.addEventListener('click', event => {
    const direction = Number(event.target.closest('[data-prototype-direction]')?.dataset.prototypeDirection || 0);
    if (direction) cycleVariant(direction);
  });
  colorMode.value = root.dataset.theme || 'system';
  colorMode.addEventListener('change', () => {
    root.dataset.theme = colorMode.value;
    localStorage.setItem('runs-theme', colorMode.value);
  });
  document.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    if (event.target.closest('input, textarea, select, [contenteditable], #route-tabs')) return;
    event.preventDefault();
    cycleVariant(event.key === 'ArrowLeft' ? -1 : 1);
  });

  function setupPlanner() {
    const form = document.querySelector('#new-run-form');
    if (!form) return;
    const intro = form.querySelector(':scope > .dialog-header + p');
    const ordinaryControls = form.querySelector(':scope > .form-grid.three');
    const advancedControls = [...form.children].find(node => node.matches('details.advanced-execution'));
    const sourceFieldset = form.querySelector(':scope > .source-fieldset');
    const actionFieldset = form.querySelector(':scope > .action-fieldset');
    const activitySummary = form.querySelector(':scope > #activity-summary');
    const formError = form.querySelector(':scope > #new-run-error');
    const reviewFooter = form.querySelector(':scope > .dialog-actions');
    if (![intro, ordinaryControls, advancedControls, sourceFieldset, actionFieldset, activitySummary, formError, reviewFooter].every(Boolean)) return;

    const progress = document.createElement('nav');
    progress.className = 'prototype-plan-progress';
    progress.setAttribute('aria-label', 'Enumeration plan progress');
    progress.innerHTML = `<ol>
      <li data-prototype-progress="1"><b>1</b><span>Target</span></li>
      <li data-prototype-progress="2"><b>2</b><span>Sources</span></li>
      <li data-prototype-progress="3"><b>3</b><span>Activity</span></li>
      <li data-prototype-progress="4"><b>4</b><span>Review</span></li>
    </ol>`;
    intro.after(progress);

    function makeStep(number, title, copy) {
      const section = document.createElement('section');
      section.id = `prototype-planner-step-${number}`;
      section.className = 'prototype-planner-step';
      section.dataset.prototypeStep = String(number);
      section.setAttribute('aria-labelledby', `prototype-planner-step-${number}-title`);
      section.innerHTML = `<header class="prototype-step-heading">
        <p class="eyebrow">Plan step ${number} of 4</p>
        <h3 id="prototype-planner-step-${number}-title" tabindex="-1">${title}</h3>
        <p>${copy}</p>
      </header>`;
      form.append(section);
      return section;
    }

    const steps = [
      makeStep(1, 'Target and limits', 'Name the authorized target and set ordinary run boundaries.'),
      makeStep(2, 'Passive source cohort', 'Choose the ready P0 sources that can collect evidence without target interaction.'),
      makeStep(3, 'Optional activity', 'P1 and P2 remain off until selected. Review every expansion of authorization.'),
      makeStep(4, 'Final authorization review', 'Confirm the exact target, source cohort, activity bands, and deadline before submission.'),
    ];
    const passiveSourceSlot = document.createElement('div');
    const activeSourceSlot = document.createElement('div');
    passiveSourceSlot.className = activeSourceSlot.className = 'prototype-source-slot';

    steps[0].append(ordinaryControls, advancedControls);
    steps[1].append(passiveSourceSlot);
    passiveSourceSlot.append(sourceFieldset);
    sourceFieldset.dataset.prototypeSourcePhase = 'passive';
    steps[2].append(activeSourceSlot, actionFieldset);
    steps[3].append(activitySummary, formError, reviewFooter);

    function stepActions(back, next, label) {
      const actions = document.createElement('footer');
      actions.className = 'prototype-step-actions';
      if (back) actions.insertAdjacentHTML('beforeend', `<button class="button" type="button" data-prototype-step-target="${back}">Back</button>`);
      if (next) actions.insertAdjacentHTML('beforeend', `<button class="button primary" type="button" data-prototype-step-target="${next}">${label}</button>`);
      return actions;
    }
    steps[0].append(stepActions(null, 2, 'Continue to sources'));
    steps[1].append(stepActions(1, 3, 'Continue to activity'));
    steps[2].append(stepActions(2, 4, 'Review authorization'));

    const reviewBack = reviewFooter.querySelector('[data-close-dialog]');
    reviewBack.removeAttribute('data-close-dialog');
    reviewBack.textContent = 'Back to activity';
    reviewBack.addEventListener('click', () => setPlannerStep(3));

    function setPlannerStep(number, focus = true) {
      state.plannerStep = number;
      steps.forEach((step, index) => { step.hidden = index + 1 !== number; });
      for (const item of progress.querySelectorAll('[data-prototype-progress]')) {
        const current = Number(item.dataset.prototypeProgress) === number;
        if (current) item.setAttribute('aria-current', 'step');
        else item.removeAttribute('aria-current');
      }
      if (number === 2) {
        passiveSourceSlot.append(sourceFieldset);
        sourceFieldset.dataset.prototypeSourcePhase = 'passive';
      } else if (number === 3) {
        activeSourceSlot.append(sourceFieldset);
        sourceFieldset.dataset.prototypeSourcePhase = 'active';
      }
      renderPrototypeState();
      if (focus) steps[number - 1].querySelector('h3').focus({preventScroll: true});
    }

    form.addEventListener('click', event => {
      const target = Number(event.target.closest('[data-prototype-step-target]')?.dataset.prototypeStepTarget || 0);
      if (target) setPlannerStep(target);
    });
    form.addEventListener('invalid', event => {
      const step = event.target.closest('[data-prototype-step]');
      if (step) setPlannerStep(Number(step.dataset.prototypeStep), false);
    }, true);
    document.addEventListener('click', event => {
      if (event.target.closest('#new-run-button, [data-action="new-run"]')) setPlannerStep(1, false);
    });
    document.querySelector('#new-run-dialog').addEventListener('close', () => setPlannerStep(1, false));
    setPlannerStep(1, false);
  }

  function setupEvidenceDistillation() {
    const assessmentReview = document.querySelector('#assessment-review');
    const providerBody = document.querySelector('#provider-body');
    const requestOptions = document.querySelector('#request-options');
    if (![assessmentReview, providerBody, requestOptions].every(Boolean)) return;

    function updateNextAction() {
      assessmentReview.querySelector('#prototype-next-action')?.remove();
      if (!assessmentReview.textContent.includes('Attention needed')) return;
      const problem = [...providerBody.rows].find(row => /partial|failed|rate-limited|skipped/i.test(row.cells[2]?.textContent || ''));
      if (!problem) return;
      const producer = problem.cells[0]?.textContent.trim() || 'the affected producer';
      const reason = problem.cells[5]?.textContent.trim() || problem.cells[2]?.textContent.trim() || 'an incomplete outcome';
      const action = document.createElement('p');
      action.id = 'prototype-next-action';
      action.className = 'prototype-next-action';
      action.textContent = `Next: review ${producer} · ${reason} before deciding whether to retry or export retained evidence.`;
      assessmentReview.append(action);
    }

    const outcomeObserver = new MutationObserver(updateNextAction);
    outcomeObserver.observe(providerBody, {childList: true});
    updateNextAction();

    function distillRequestOptions() {
      optionObserver.disconnect();
      document.querySelector('#prototype-inactive-options')?.remove();
      const options = [...requestOptions.children];
      const inactive = options.filter(option => /^(Off|Not recorded|Not applicable)$/.test(option.querySelector('dd')?.textContent.trim() || ''));
      if (inactive.length) {
        const details = document.createElement('details');
        details.id = 'prototype-inactive-options';
        details.className = 'prototype-inactive-options';
        details.innerHTML = `<summary>${inactive.length} inactive or unrecorded options</summary><dl class="request-options"></dl>`;
        details.querySelector('dl').append(...inactive);
        requestOptions.after(details);
      }
      optionObserver.observe(requestOptions, {childList: true});
    }

    const optionObserver = new MutationObserver(distillRequestOptions);
    optionObserver.observe(requestOptions, {childList: true});
    distillRequestOptions();
  }

  function setupScheduleHierarchy() {
    const scheduleList = document.querySelector('#schedule-list');
    if (!scheduleList) return;

    function enhanceCards() {
      for (const card of scheduleList.querySelectorAll('.schedule-card:not([data-prototype-actions])')) {
        card.dataset.prototypeActions = 'distilled';
        const actions = card.querySelector('.schedule-card-footer .compact-actions');
        const deleteButton = actions?.querySelector('[data-action="delete"]');
        if (!actions || !deleteButton) continue;
        actions.classList.add('prototype-schedule-peer-actions');
        actions.querySelector('[data-action="run-now"]')?.classList.add('prototype-run-now');
        const disclosure = document.createElement('details');
        disclosure.className = 'prototype-delete-disclosure';
        disclosure.innerHTML = `<summary>Delete schedule…</summary><p>Removes this reusable plan. Existing run evidence remains intact.</p>`;
        disclosure.append(deleteButton);
        card.querySelector('.schedule-card-footer').after(disclosure);
      }
    }

    new MutationObserver(enhanceCards).observe(scheduleList, {childList: true});
    enhanceCards();
  }

  setVariant(initialVariant);
  setupPlanner();
  setupEvidenceDistillation();
  setupScheduleHierarchy();
})();
