document.addEventListener('DOMContentLoaded', () => {
    const api = new AuthAdminAPI();

    function showLogin() {
        document.getElementById('login').classList.remove('hidden');
        document.getElementById('main').classList.add('hidden');
    }

    function showMain() {
        document.getElementById('login').classList.add('hidden');
        document.getElementById('main').classList.remove('hidden');
        api.refreshAll();
    }

    document.getElementById('btnLogin').addEventListener('click', async () => {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const success = await api.login(email, password);
        if (success) {
            showMain();
        }
    });

    // Header user menu
    const menuBtn = document.getElementById('userMenuBtn');
    const menu = document.getElementById('userMenu');
    const logoutItem = document.getElementById('menuLogout');
    menuBtn?.addEventListener('click', () => {
        menu.classList.toggle('visible');
    });
    document.addEventListener('click', (e)=>{
        if(!menu.contains(e.target) && e.target !== menuBtn){ menu.classList.remove('visible'); }
    });
    logoutItem?.addEventListener('click', ()=>{ api.logout(); showLogin(); });

    document.getElementById('btnOpenAddUserModal').addEventListener('click', () => api.openAddUserModal());
    document.getElementById('btnOpenAddRoleModal').addEventListener('click', () => api.openAddRoleModal());

    // Modal close events
    document.getElementById('modalOverlay').addEventListener('click', (e) => {
        if (e.target.id === 'modalOverlay') {
            api.closeModal();
        }
    });
    document.getElementById('modalClose').addEventListener('click', () => api.closeModal());


    // Auto-login attempt
    if (api.isLoggedIn()) {
        showMain();
    } else {
        showLogin();
    }
});

class AuthAdminAPI {
    constructor() {
        this.base = '';
        this.storageKey = 'auth_token';
        this.token = localStorage.getItem(this.storageKey) || '';
        this.roles = [];
        this.users = [];
        this.filteredUsers = [];
        this.sortKey = 'id';
        this.sortDir = 'asc';
        this.page = 1;
        this.pageSize = 10;
        this.loadingEl = document.getElementById('loadingOverlay');
        this.toastEl = document.getElementById('toast');
        this.bindUX();
    }

    bindUX() {
        const q = (id) => document.getElementById(id);
        q('searchUser')?.addEventListener('input', ()=> this.applyFilters());
        q('filterRole')?.addEventListener('change', ()=> this.applyFilters());
        q('filterStatus')?.addEventListener('change', ()=> this.applyFilters());
        q('prevPage')?.addEventListener('click', ()=> { if(this.page>1){ this.page--; this.renderUsers(); } });
        q('nextPage')?.addEventListener('click', ()=> { const max = Math.ceil(this.filteredUsers.length/this.pageSize)||1; if(this.page<max){ this.page++; this.renderUsers(); } });
        // sortable headers
        document.querySelectorAll('#usersTable thead th[data-sort]')?.forEach(th=>{
            th.addEventListener('click', ()=>{
                const key = th.getAttribute('data-sort');
                if(this.sortKey===key){ this.sortDir = this.sortDir==='asc'?'desc':'asc'; } else { this.sortKey=key; this.sortDir='asc'; }
                this.renderUsers();
            });
        });
    }

    showLoading(on=true){ if(this.loadingEl){ this.loadingEl.style.display = on ? 'flex':'none'; } }
    toast(msg, kind='success'){ if(!this.toastEl) return; this.toastEl.textContent = msg; this.toastEl.className = ''; this.toastEl.classList.add(kind==='error'?'error':'success'); this.toastEl.style.display='block'; setTimeout(()=>{ this.toastEl.style.display='none'; }, 2500); }

    async authFetch(path, opts = {}) {
        opts.headers = { ...opts.headers, 'Content-Type': 'application/json' };
        if (this.token) opts.headers['Authorization'] = 'Bearer ' + this.token;
        this.showLoading(true);
        try{
            const res = await fetch(this.base + path, opts);
            if(res.status === 401){ this.logout(); this.toast('Session expired. Please log in again.','error'); throw new Error('Unauthorized'); }
            return res;
        } finally { this.showLoading(false); }
    }

    isLoggedIn() { return !!this.token; }
    setLoginMessage(msg) { document.getElementById('loginMsg').textContent = msg; }

    async login(email, password) {
        this.setLoginMessage('');
        try {
            const res = await this.authFetch('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password }),
            });
            if (!res.ok) {
                const errorData = await res.json().catch(() => ({ detail: 'Unknown error' }));
                this.setLoginMessage(`Login failed: ${errorData.detail || res.statusText}`);
                return false;
            }
            const data = await res.json();
            this.token = data.access_token;
            localStorage.setItem(this.storageKey, this.token);
            // update avatar initial
            const avatar = document.getElementById('avatarInitial');
            const ch = (email||'U').trim().charAt(0).toUpperCase();
            if(avatar) avatar.textContent = ch;
            return true;
        } catch (e) {
            this.setLoginMessage(e.message);
            return false;
        }
    }

    logout() {
        this.token = '';
        localStorage.removeItem(this.storageKey);
    // close menu if open
    const menu = document.getElementById('userMenu');
    if(menu) menu.classList.remove('visible');
    document.getElementById('login').classList.remove('hidden');
    document.getElementById('main').classList.add('hidden');
    }
    
    async refreshAll() {
        await this.loadRoles();
        await this.loadUsers();
    }

    async loadRoles() {
        try {
            const res = await this.authFetch('/auth/admin/roles');
            if (!res.ok) throw new Error(`Failed to load roles: ${res.status}`);
            const payload = await res.json();
            this.roles = (Array.isArray(payload) ? payload : []).map(r => typeof r === 'object' ? r : { name: r, description: '' });
            this.renderRoles();
        } catch (e) {
            console.error(e);
        }
    }

    renderRoles() {
        const rolesList = document.getElementById('rolesList');
        rolesList.innerHTML = '';
        this.roles.forEach(role => {
            const roleEl = document.createElement('div');
            roleEl.className = 'role-item';
            roleEl.innerHTML = `
                <div class="role-main" style="cursor:pointer">
                    <strong>${role.name}</strong>
                    <p>${role.description || 'No description'}</p>
                </div>
                <div>
                  <button class="btn-secondary" data-action="edit">Edit</button>
                  <button class="btn-danger" data-action="remove" ${role.name === 'admin' ? 'disabled title="Cannot remove admin"' : ''}>Remove</button>
                </div>
            `;
            roleEl.querySelector('.role-main').addEventListener('click', () => this.openEditRoleModal(role));
            roleEl.querySelector('[data-action="edit"]').addEventListener('click', () => this.openEditRoleModal(role));
            const removeBtn = roleEl.querySelector('[data-action="remove"]');
            if (!removeBtn.disabled) {
              removeBtn.addEventListener('click', () => this.openRemoveRoleModal(role.name));
            }
            rolesList.appendChild(roleEl);
        });
        // styles for list
        const style = document.createElement('style');
        style.innerHTML = `
            .role-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; border-bottom: 1px solid var(--border-color); }
            .role-item:last-child { border-bottom: none; }
            .role-item p { margin: 0; font-size: 0.9em; color: var(--text-muted); }
        `;
        document.head.appendChild(style);
    }

    async loadUsers() {
        try {
            const res = await this.authFetch('/users/');
            if (!res.ok) throw new Error(`Failed to load users: ${res.status}`);
            this.users = await res.json();
            // populate role filter
            const roleSet = new Set();
            this.users.forEach(u=> u.roles.forEach(r=> roleSet.add(r)));
            const filterRole = document.getElementById('filterRole');
            if(filterRole){
              const cur = filterRole.value;
              filterRole.innerHTML = '<option value="">All roles</option>' + Array.from(roleSet).sort().map(r=>`<option value="${r}">${r}</option>`).join('');
              if(cur) filterRole.value = cur;
            }
            this.applyFilters();
        } catch (e) { console.error(e); this.toast(e.message,'error'); }
    }

    applyFilters(){
        const q = (id) => document.getElementById(id);
        const term = (q('searchUser')?.value || '').toLowerCase();
        const role = q('filterRole')?.value || '';
        const status = q('filterStatus')?.value || '';
        this.filteredUsers = this.users.filter(u=>{
            if(term && !u.email.toLowerCase().includes(term)) return false;
            if(role && !u.roles.includes(role)) return false;
            if(status==='active' && !u.is_active) return false;
            if(status==='inactive' && u.is_active) return false;
            return true;
        });
        this.page = 1;
        this.renderUsers();
    }

    renderUsers(){
        // sort
        const dir = this.sortDir==='asc'?1:-1;
        const key = this.sortKey;
        const list = [...this.filteredUsers].sort((a,b)=>{
            const av = a[key]; const bv = b[key];
            if(av===bv) return 0; return av>bv?dir:-dir;
        });
        const tbody = document.querySelector('#usersTable tbody');
        tbody.innerHTML = '';
        // pagination
        const start = (this.page-1)*this.pageSize; const end = start + this.pageSize;
        const pageItems = list.slice(start, end);
        pageItems.forEach(user => {
            const tr = document.createElement('tr');
            const rolesHtml = user.roles.map(r => `<span class="role-tag">${r}</span>`).join(' ');
            tr.innerHTML = `
                <td><a href="#" data-action="detail">${user.id}</a></td>
                <td>${user.email}</td>
                <td>${rolesHtml}</td>
                <td>${user.is_active ? 'Yes' : 'No'}</td>
                <td class="actions">
                    <button class="btn-secondary" data-action="approve">${user.is_active ? 'Deactivate' : 'Activate'}</button>
                    <button class="btn-secondary" data-action="password">Reset Link</button>
                    <button class="btn-secondary" data-action="assign">Assign Role</button>
                    <button class="btn-danger" data-action="remove">Remove</button>
                </td>
            `;
            tr.querySelector('[data-action="detail"]').addEventListener('click', (e) => { e.preventDefault(); this.openUserDetailModal(user); });
            tr.querySelector('[data-action="approve"]').addEventListener('click', () => this.openApproveUserModal(user.email, !user.is_active));
            tr.querySelector('[data-action="password"]').addEventListener('click', () => this.openResetPasswordLinkModal(user.email));
            tr.querySelector('[data-action="assign"]').addEventListener('click', () => this.openAssignRoleModal(user.email, user.roles));
            tr.querySelector('[data-action="remove"]').addEventListener('click', () => this.openRemoveUserModal(user.email));
            tbody.appendChild(tr);
        });
        const info = document.getElementById('usersInfo');
        if(info){
          const total = this.filteredUsers.length; const max = Math.ceil(total/this.pageSize)||1; const startNo = total?start+1:0; const endNo = Math.min(end, total);
          info.textContent = `Showing ${startNo}-${endNo} of ${total}`;
          document.getElementById('prevPage').disabled = this.page<=1;
          document.getElementById('nextPage').disabled = this.page>=max;
        }
    }

    openUserDetailModal(user) {
        const content = `
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Created:</strong> ${user.created_at || '-'}</p>
            <p><strong>Last login:</strong> ${user.last_login || '-'}</p>
            <p><strong>Status:</strong> ${user.is_active ? 'Active' : 'Inactive'}</p>
            <p><strong>Roles:</strong> ${user.roles.map(r => `<span class='role-tag'>${r}</span>`).join(' ')}</p>
        `;
        this.openModal('User Details', content, null);
    }

    openResetPasswordLinkModal(email) {
        const content = `<p>Create a one-time reset link for <strong>${email}</strong>? It will expire based on PASSWORD_RESET_EXPIRES_MINUTES.</p>`;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Generate Link';
        btn.addEventListener('click', async () => {
            const res = await this.authFetch('/users/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) });
            if (!res.ok) { alert('Failed to create link'); return; }
            const data = await res.json();
            const publicBase = (window.PUBLIC_BASE_URL || document.querySelector('meta[name="public-base-url"]')?.content || '').trim();
            const full = (publicBase || window.location.origin) + data.reset_link;
            await navigator.clipboard.writeText(full).catch(()=>{});
            this.closeModal();
            alert('Reset link copied to clipboard: ' + full);
        });
        actions.appendChild(btn);
        this.openModal('Password Reset Link', content, actions);
    }

    // MODAL CONTROLS
    openModal(title, content, actions) {
        document.getElementById('modalTitle').innerHTML = title;
        document.getElementById('modalContent').innerHTML = content;
        const actionsContainer = document.getElementById('modalActions');
        actionsContainer.innerHTML = '';
        if (actions) actionsContainer.appendChild(actions);
        document.getElementById('modalOverlay').classList.add('visible');
    }

    closeModal() {
        document.getElementById('modalOverlay').classList.remove('visible');
    }

    // MODAL DEFINITIONS
    openAddUserModal() {
        const content = `
            <input id="newUserEmail" type="email" placeholder="Email" required>
            <input id="newUserPassword" type="password" placeholder="Password" required>
            <div id="addUserMsg" class="message error-msg"></div>
        `;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Add User';
        btn.addEventListener('click', async () => {
            const email = document.getElementById('newUserEmail').value;
            const password = document.getElementById('newUserPassword').value;
            if (!email || !password) {
                document.getElementById('addUserMsg').textContent = 'Email and password are required.';
                return;
            }
            await this.addUser(email, password);
        });
        actions.appendChild(btn);
        this.openModal('Add New User', content, actions);
    }
    
    openAddRoleModal() {
        const content = `
            <input id="newRoleName" type="text" placeholder="Role Name" required>
            <input id="newRoleDesc" type="text" placeholder="Description (optional)">
            <div id="addRoleMsg" class="message error-msg"></div>
        `;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Add Role';
        btn.addEventListener('click', async () => {
            const name = document.getElementById('newRoleName').value;
            const description = document.getElementById('newRoleDesc').value;
            if (!name) {
                document.getElementById('addRoleMsg').textContent = 'Role name is required.';
                return;
            }
            await this.addRole(name, description);
        });
        actions.appendChild(btn);
        this.openModal('Add New Role', content, actions);
    }

    openApproveUserModal(email, approve) {
        const actionText = approve ? 'Approve' : 'Deactivate';
        const content = `<p>Are you sure you want to ${actionText.toLowerCase()} user <strong>${email}</strong>?</p>`;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = approve ? 'btn-success' : 'btn-danger';
        btn.textContent = actionText;
        btn.addEventListener('click', () => this.approveUser(email, approve));
        actions.appendChild(btn);
        this.openModal(`${actionText} User`, content, actions);
    }

    openChangePasswordModal(email) {
        const content = `
            <p>Set new password for <strong>${email}</strong>:</p>
            <input id="newPassword" type="password" placeholder="New Password" required>
            <div id="cpMsg" class="message error-msg"></div>
        `;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Set Password';
        btn.addEventListener('click', () => {
            const newPassword = document.getElementById('newPassword').value;
            if (!newPassword) {
                document.getElementById('cpMsg').textContent = 'Password cannot be empty.';
                return;
            }
            this.changePassword(email, newPassword);
        });
        actions.appendChild(btn);
        this.openModal('Change Password', content, actions);
    }

    openAssignRoleModal(email, currentRoles) {
        const availableRoles = this.roles.filter(r => !currentRoles.includes(r.name));
        let content = `<p>Assign a new role to <strong>${email}</strong>.</p>`;
        if (availableRoles.length > 0) {
            content += `<select id="assignRoleSelect">` + availableRoles.map(r => `<option value="${r.name}">${r.name}</option>`).join('') + `</select>`;
        } else {
            content += `<p>No new roles available to assign.</p>`;
        }
        
        const actions = document.createElement('div');
        if (availableRoles.length > 0) {
            const btn = document.createElement('button');
            btn.className = 'btn';
            btn.textContent = 'Assign';
            btn.addEventListener('click', () => {
                const role = document.getElementById('assignRoleSelect').value;
                this.assignRole(email, role);
            });
            actions.appendChild(btn);
        }

        if (currentRoles.length > 0) {
            content += `<hr style="margin: 1rem 0;"><p>Or unassign an existing role:</p>`;
            content += `<select id="unassignRoleSelect">` + currentRoles.map(r => `<option value="${r}">${r}</option>`).join('') + `</select>`;
            const btnUnassign = document.createElement('button');
            btnUnassign.className = 'btn-danger';
            btnUnassign.textContent = 'Unassign';
            btnUnassign.addEventListener('click', () => {
                const role = document.getElementById('unassignRoleSelect').value;
                this.unassignRole(email, role);
            });
            actions.appendChild(btnUnassign);
        }

        this.openModal('Manage Roles', content, actions);
    }

    openRemoveUserModal(email) {
        const content = `<p>This action is irreversible. Are you sure you want to remove user <strong>${email}</strong>?</p>`;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn-danger';
        btn.textContent = 'Confirm Remove';
        btn.addEventListener('click', () => this.removeUser(email));
        actions.appendChild(btn);
        this.openModal('Remove User', content, actions);
    }

    openRemoveRoleModal(roleName) {
        const content = `<p>Are you sure you want to remove the role <strong>${roleName}</strong>? This will not unassign it from users who currently have it.</p>`;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn-danger';
        btn.textContent = 'Confirm Remove';
        btn.addEventListener('click', () => this.removeRole(roleName));
        actions.appendChild(btn);
        this.openModal('Remove Role', content, actions);
    }

    // API CALLS
    async addUser(email, password) {
        try {
            const res = await this.authFetch('/auth/admin/add-user', {
                method: 'POST',
                body: JSON.stringify({ email, password, roles: ['visitor'] }),
            });
            if (!res.ok) {
                const error = await res.json();
                document.getElementById('addUserMsg').textContent = `Error: ${error.detail}`;
                return;
            }
            this.closeModal();
            await this.refreshAll();
        } catch (e) {
            document.getElementById('addUserMsg').textContent = e.message;
        }
    }

    async addRole(role, description) {
        try {
            const res = await this.authFetch('/auth/admin/add-role', {
                method: 'POST',
                body: JSON.stringify({ role, description }),
            });
            if (!res.ok) {
                const error = await res.json();
                document.getElementById('addRoleMsg').textContent = `Error: ${error.detail}`;
                return;
            }
            this.closeModal();
            await this.loadRoles();
        } catch (e) {
            document.getElementById('addRoleMsg').textContent = e.message;
        }
    }

    async approveUser(email, approve) {
        try {
            const res = await this.authFetch('/auth/admin/approve-user', {
                method: 'POST',
                body: JSON.stringify({ email, approve }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
            await this.loadUsers();
        } catch (e) {
            alert(`Failed: ${e.message}`);
        }
    }

    async changePassword(email, new_password) {
        try {
            const res = await this.authFetch('/auth/admin/change-password', {
                method: 'POST',
                body: JSON.stringify({ email, new_password }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
        } catch (e) {
            document.getElementById('cpMsg').textContent = `Failed: ${e.message}`;
        }
    }
    
    async assignRole(email, role) {
        try {
            const res = await this.authFetch('/auth/assign-role', {
                method: 'POST',
                body: JSON.stringify({ email, role }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
            await this.refreshAll();
        } catch (e) {
            alert(`Failed: ${e.message}`);
        }
    }

    async unassignRole(email, role) {
        try {
            const res = await this.authFetch('/auth/assign-role-unassign', {
                method: 'POST',
                body: JSON.stringify({ email, role, unassign: true }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
            await this.refreshAll();
        } catch (e) {
            alert(`Failed: ${e.message}`);
        }
    }

    async removeUser(email) {
        try {
            const res = await this.authFetch('/auth/admin/remove-user', {
                method: 'POST',
                body: JSON.stringify({ email }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
            await this.loadUsers();
        } catch (e) {
            alert(`Failed: ${e.message}`);
        }
    }

    async removeRole(role) {
        try {
            const res = await this.authFetch('/auth/admin/remove-role', {
                method: 'POST',
                body: JSON.stringify({ role }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.closeModal();
            await this.loadRoles();
        } catch (e) {
            alert(`Failed: ${e.message}`);
        }
    }

    openEditRoleModal(role) {
        const content = `
            <input id="editRoleName" type="text" placeholder="Role Name" value="${role.name}">
            <input id="editRoleDesc" type="text" placeholder="Description" value="${role.description || ''}">
            <div id="editRoleMsg" class="message error-msg"></div>
        `;
        const actions = document.createElement('div');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Save';
        btn.addEventListener('click', async () => {
            const new_name = document.getElementById('editRoleName').value.trim();
            const description = document.getElementById('editRoleDesc').value;
            const payload = { role: role.name };
            if (new_name && new_name !== role.name) payload.new_name = new_name;
            payload.description = description;
            const res = await this.authFetch('/auth/admin/update-role', { method: 'POST', body: JSON.stringify(payload) });
            if (!res.ok) {
                const err = await res.json().catch(()=>({detail:'Error'}));
                document.getElementById('editRoleMsg').textContent = err.detail || 'Failed';
                return;
            }
            this.closeModal();
            await this.loadRoles();
        });
        actions.appendChild(btn);
        this.openModal('Edit Role', content, actions);
    }
}
