(function () {
    'use strict';
    var root = document.documentElement;
    var single = document.body.classList.contains('single');
    var pages = Array.prototype.slice.call(document.querySelectorAll('section.page'));

    function $$(scope, sel) { return Array.prototype.slice.call(scope.querySelectorAll(sel)); }
    function store(key, value) {
        try {
            if (value === undefined) { return window.localStorage.getItem(key); }
            window.localStorage.setItem(key, value);
        } catch (e) { return null; }
        return null;
    }

    /* Theme */
    var savedTheme = store('ldd-theme');
    if (savedTheme) { root.setAttribute('data-theme', savedTheme); }
    $$(document, '.theme-toggle').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var dark = root.getAttribute('data-theme') === 'dark' ||
                (!root.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
            var next = dark ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            store('ldd-theme', next);
        });
    });

    var numeric = /^-?\d+(\.\d+)?$/;
    function compare(a, b) {
        if (numeric.test(a) && numeric.test(b)) { return parseFloat(a) - parseFloat(b); }
        if (a === '' && b !== '') { return 1; }
        if (b === '' && a !== '') { return -1; }
        return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
    }
    function cellValue(row, idx) {
        var cell = row.cells[idx];
        if (!cell) { return ''; }
        var v = cell.getAttribute('data-sort');
        return v !== null ? v : cell.textContent.trim();
    }
    function cellText(cell) {
        var sid = cell.querySelector('abbr.sid');
        if (sid) { return sid.getAttribute('title'); }
        var parts = cell.querySelectorAll('.badge:not(.tag), .spn, .item, a');
        if (parts.length > 1) {
            return Array.prototype.map.call(parts, function (p) { return p.textContent.trim(); }).join(', ');
        }
        return cell.textContent.trim();
    }
    function headerRow(table) {
        return table.querySelector('thead tr') || table.querySelector('tr.hdr');
    }

    function initPage(page) {
        var tables = $$(page, 'table.report');
        var trees = $$(page, 'ul.tree');
        var search = page.querySelector('.filter');
        var counter = page.querySelector('.row-count');
        var hideDisabled = page.querySelector('.hide-disabled');
        var bodies = [];
        tables.forEach(function (t) { bodies = bodies.concat(Array.prototype.slice.call(t.tBodies)); });
        var treeItems = [];
        trees.forEach(function (t) { treeItems = treeItems.concat($$(t, 'li')); });

        function rowsOf(tbody) { return $$(tbody, 'tr.row'); }
        function isHiddenRow(r) {
            return r.hidden || r.parentNode.hidden || (hideDisabled && hideDisabled.checked && r.classList.contains('disabled'));
        }

        function updateCount() {
            if (!counter) { return; }
            if (trees.length) {
                var vis = treeItems.filter(function (li) { return !li.hidden; }).length;
                counter.textContent = vis === treeItems.length ? treeItems.length + ' entries' : vis + ' / ' + treeItems.length + ' entries';
                return;
            }
            var visible = 0, total = 0;
            bodies.forEach(function (b) {
                if (b.closest('table').classList.contains('kv')) { return; }
                rowsOf(b).forEach(function (r) { total++; if (!isHiddenRow(r)) { visible++; } });
            });
            var groups = bodies.filter(function (b) { return b.classList.contains('grp'); });
            var groupsTxt = groups.length ? groups.filter(function (b) { return !b.hidden; }).length + ' / ' + groups.length + ' groups · ' : '';
            counter.textContent = groupsTxt + (visible === total ? total + ' entries' : visible + ' / ' + total + ' entries');
        }

        /* Filtering */
        function filterTree(li, q) {
            var own = li.querySelector(':scope > details > summary, :scope > .leaf');
            var selfMatch = q === '' || (own && own.textContent.toLowerCase().indexOf(q) !== -1);
            var childMatch = false;
            $$(li, ':scope > details > ul > li').forEach(function (child) {
                if (filterTree(child, selfMatch && q !== '' ? '' : q)) { childMatch = true; }
            });
            var visible = selfMatch || childMatch;
            li.hidden = !visible;
            var details = li.querySelector(':scope > details');
            if (details && q !== '' && childMatch) { details.open = true; }
            return visible;
        }
        function applyFilter() {
            var q = search ? search.value.trim().toLowerCase() : '';
            bodies.forEach(function (b) {
                var title = b.querySelector('tr.grp-title');
                var titleMatch = q === '' || (title && title.textContent.toLowerCase().indexOf(q) !== -1);
                var anyVisible = false;
                rowsOf(b).forEach(function (r) {
                    var match = titleMatch || r.textContent.toLowerCase().indexOf(q) !== -1;
                    r.hidden = !match;
                    if (match) { anyVisible = true; }
                });
                if (b.classList.contains('grp')) {
                    b.hidden = !(titleMatch || anyVisible);
                    if (q !== '' && anyVisible) { b.classList.remove('collapsed'); }
                }
            });
            trees.forEach(function (t) { $$(t, ':scope > li').forEach(function (li) { filterTree(li, q); }); });
            updateCount();
        }
        var timer = null;
        if (search) {
            search.addEventListener('input', function () {
                clearTimeout(timer);
                timer = setTimeout(applyFilter, 150);
            });
        }
        if (hideDisabled) {
            hideDisabled.checked = store('ldd-hide-disabled') === '1';
            var applyHide = function () {
                page.classList.toggle('hide-disabled', hideDisabled.checked);
                store('ldd-hide-disabled', hideDisabled.checked ? '1' : '0');
                updateCount();
            };
            hideDisabled.addEventListener('change', applyHide);
            applyHide();
        }

        /* Sorting and collapsing */
        tables.forEach(function (table) {
            table.addEventListener('click', function (e) {
                var th = e.target.closest('th');
                if (th && !table.classList.contains('kv')) {
                    var headRow = th.parentNode;
                    var idx = Array.prototype.indexOf.call(headRow.cells, th);
                    var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
                    Array.prototype.forEach.call(headRow.cells, function (c) { c.removeAttribute('aria-sort'); });
                    th.setAttribute('aria-sort', dir);
                    var scope = table.classList.contains('grouped') ? [headRow.parentNode] : Array.prototype.slice.call(table.tBodies);
                    scope.forEach(function (b) {
                        var rows = rowsOf(b);
                        rows.sort(function (x, y) {
                            var r = compare(cellValue(x, idx), cellValue(y, idx));
                            return dir === 'ascending' ? r : -r;
                        });
                        rows.forEach(function (r) { b.appendChild(r); });
                    });
                    return;
                }
                var title = e.target.closest('tr.grp-title');
                if (title && !e.target.closest('a')) { title.parentNode.classList.toggle('collapsed'); }
            });
        });
        function setAll(collapsed) {
            bodies.forEach(function (b) { if (b.classList.contains('grp')) { b.classList.toggle('collapsed', collapsed); } });
            trees.forEach(function (t) { $$(t, 'details').forEach(function (d) { d.open = !collapsed; }); });
        }
        var expand = page.querySelector('.expand-all');
        var collapse = page.querySelector('.collapse-all');
        if (expand) { expand.addEventListener('click', function () { setAll(false); }); }
        if (collapse) { collapse.addEventListener('click', function () { setAll(true); }); }

        /* Column chooser */
        var colmenu = page.querySelector('.colmenu-list');
        if (colmenu && tables.length) {
            var hdr = headerRow(tables[0]);
            var labels = Array.prototype.map.call(hdr.cells, function (c) { return c.textContent.trim(); });
            var key = 'ldd-cols-' + page.id;
            var saved = store(key);
            var hidden;
            try { hidden = saved ? JSON.parse(saved) : null; } catch (e) { hidden = null; }
            if (!hidden) {
                hidden = Array.prototype.filter.call(hdr.cells, function (c) { return c.getAttribute('data-hidden'); })
                    .map(function (c) { return c.textContent.trim(); });
            }
            var style = document.createElement('style');
            page.appendChild(style);
            var applyCols = function () {
                var rules = [];
                labels.forEach(function (label, i) {
                    if (hidden.indexOf(label) !== -1) {
                        rules.push('#' + page.id + ' table.report tr:not(.grp-title) > :nth-child(' + (i + 1) + ') { display: none; }');
                    }
                });
                style.textContent = rules.join('\n');
            };
            labels.forEach(function (label) {
                var item = document.createElement('label');
                var box = document.createElement('input');
                box.type = 'checkbox';
                box.checked = hidden.indexOf(label) === -1;
                box.addEventListener('change', function () {
                    if (box.checked) { hidden = hidden.filter(function (h) { return h !== label; }); } else { hidden.push(label); }
                    store(key, JSON.stringify(hidden));
                    applyCols();
                });
                item.appendChild(box);
                item.appendChild(document.createTextNode(' ' + label));
                colmenu.appendChild(item);
            });
            applyCols();
        }

        /* CSV export of the visible rows and columns */
        var csvBtn = page.querySelector('.csv-export');
        if (csvBtn) {
            csvBtn.addEventListener('click', function () {
                var quote = function (v) { return /[",\n;]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
                var lines = [];
                var exportable = tables.filter(function (t) { return !t.classList.contains('kv'); });
                exportable.forEach(function (table, n) {
                    var head = headerRow(table);
                    if (!head) { return; }
                    var visibleCols = [];
                    Array.prototype.forEach.call(head.cells, function (c, i) {
                        if (window.getComputedStyle(c).display !== 'none') { visibleCols.push(i); }
                    });
                    var grouped = table.classList.contains('grouped');
                    if (exportable.length > 1) {
                        var title = table.closest('.card').querySelector('.card-head h2');
                        if (n) { lines.push(''); }
                        lines.push(quote(title ? title.textContent : 'Table ' + (n + 1)));
                    }
                    lines.push((grouped ? ['Group'] : []).concat(visibleCols.map(function (i) { return quote(head.cells[i].textContent.trim()); })).join(','));
                    Array.prototype.forEach.call(table.tBodies, function (b) {
                        if (b.hidden) { return; }
                        var t = b.querySelector('tr.grp-title');
                        var groupName = t ? t.firstElementChild.firstChild.textContent.trim() : '';
                        rowsOf(b).forEach(function (r) {
                            if (isHiddenRow(r)) { return; }
                            var cells = visibleCols.map(function (i) { return quote(r.cells[i] ? cellText(r.cells[i]) : ''); });
                            lines.push((grouped ? [quote(groupName)] : []).concat(cells).join(','));
                        });
                    });
                });
                var blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
                var a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = page.id + '.csv';
                document.body.appendChild(a);
                a.click();
                setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
            });
        }

        /* Membership explorer */
        var dataEl = page.querySelector('script.membership-data');
        if (dataEl) { initExplorer(page, JSON.parse(dataEl.textContent).nodes); }

        page.applyFilter = applyFilter;
        updateCount();
    }

    function initExplorer(page, nodes) {
        var input = page.querySelector('.explorer-input');
        var results = page.querySelector('.explorer-results');
        var view = page.querySelector('.explorer-view');
        var children = nodes.map(function () { return []; });
        nodes.forEach(function (n, i) { n[3].forEach(function (p) { children[p].push(i); }); });
        var kinds = { u: 'user', g: 'group', c: 'computer' };
        var LIMIT = 3000;

        function esc(s) {
            return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
        }
        function label(i) {
            var n = nodes[i];
            return '<span class="badge tag">' + kinds[n[1]] + '</span> <a href="#" class="explore" data-idx="' + i + '" title="' + esc(n[2]) + '">' + esc(n[0]) + '</a>';
        }
        function tree(start, next) {
            var count = 0;
            function render(i, seen, depth) {
                var kids = next(i).filter(function (k) { return seen.indexOf(k) === -1; });
                kids.sort(function (a, b) { return nodes[a][0].localeCompare(nodes[b][0]); });
                var html = '';
                kids.forEach(function (k) {
                    if (count++ > LIMIT) { return; }
                    var sub = depth < 30 ? render(k, seen.concat([k]), depth + 1) : '';
                    html += sub ? '<li><details' + (depth < 1 ? ' open' : '') + '><summary>' + label(k) + '</summary><ul>' + sub + '</ul></details></li>'
                        : '<li><span class="leaf">' + label(k) + '</span></li>';
                });
                return html;
            }
            var html = render(start, [start], 0);
            if (count > LIMIT) { html += '<li class="node-desc">Truncated after ' + LIMIT + ' entries</li>'; }
            return html ? '<ul class="tree">' + html + '</ul>' : '<div class="empty">None</div>';
        }
        function flat(start, next) {
            var seen = {}, queue = [start], out = 0;
            seen[start] = true;
            while (queue.length) {
                next(queue.shift()).forEach(function (k) { if (!seen[k]) { seen[k] = true; out++; queue.push(k); } });
            }
            return out;
        }
        function show(i) {
            var n = nodes[i];
            var parents = function (k) { return nodes[k][3]; };
            var kids = function (k) { return children[k]; };
            var html = '<div class="explorer-head"><h2>' + esc(n[0]) + ' <span class="badge tag">' + kinds[n[1]] + '</span></h2><div class="node-desc">' + esc(n[2]) + '</div></div>';
            html += '<div class="cols2"><div><h3>Member of <span class="count">' + flat(i, parents) + ' recursive</span></h3>' + tree(i, parents) + '</div>';
            if (n[1] === 'g') {
                html += '<div><h3>Members <span class="count">' + flat(i, kids) + ' recursive</span></h3>' + tree(i, kids) + '</div>';
            }
            html += '</div>';
            view.innerHTML = html;
            results.innerHTML = '';
            input.value = n[0];
        }
        function search() {
            var q = input.value.trim().toLowerCase();
            if (!q) { results.innerHTML = ''; return; }
            var found = [];
            for (var i = 0; i < nodes.length && found.length < 25; i++) {
                if (nodes[i][0].toLowerCase().indexOf(q) !== -1) { found.push(i); }
            }
            results.innerHTML = found.map(function (i) { return '<li>' + label(i) + '</li>'; }).join('') || '<li class="node-desc">No match</li>';
        }
        input.addEventListener('input', search);
        page.addEventListener('click', function (e) {
            var a = e.target.closest('a.explore');
            if (a) { e.preventDefault(); show(parseInt(a.getAttribute('data-idx'), 10)); }
        });
    }

    pages.forEach(initPage);

    /* Close the column menus when clicking elsewhere */
    document.addEventListener('click', function (e) {
        $$(document, 'details.colmenu[open]').forEach(function (d) { if (!d.contains(e.target)) { d.open = false; } });
    });

    /* Keyboard: / focuses the filter of the visible page */
    document.addEventListener('keydown', function (e) {
        var page = pages.filter(function (p) { return !p.hidden; })[0];
        if (!page) { return; }
        var search = page.querySelector('.filter, .explorer-input');
        if (!search) { return; }
        if (e.key === '/' && document.activeElement !== search && !/input|textarea/i.test(document.activeElement.tagName)) {
            e.preventDefault();
            search.focus();
        }
        if (e.key === 'Escape' && document.activeElement === search) {
            search.value = '';
            if (page.applyFilter) { page.applyFilter(); }
            search.blur();
        }
    });

    /* Navigation: anchors and, in single file mode, switching between pages */
    var navLinks = $$(document, '.nav a');
    function showPage(id) {
        pages.forEach(function (p) { p.hidden = p.id !== id; });
        navLinks.forEach(function (a) { a.classList.toggle('active', a.getAttribute('data-page') === id); });
    }
    function openTarget() {
        var hash = decodeURIComponent(location.hash.slice(1));
        var target = hash ? document.getElementById(hash) : null;
        if (single) {
            if (target && target.matches('section.page')) {
                showPage(target.id);
                window.scrollTo(0, 0);
                return;
            }
            var page = target ? target.closest('section.page') : null;
            showPage(page ? page.id : (pages[0] && pages[0].id));
        }
        if (target && target.classList.contains('grp')) {
            target.hidden = false;
            target.classList.remove('collapsed');
            target.scrollIntoView();
        }
    }
    window.addEventListener('hashchange', openTarget);
    openTarget();
})();
