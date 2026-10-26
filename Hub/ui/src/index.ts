import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    redirect: '/dashboard'
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('./views/Dashboard.vue')
  },
  {
    path: '/fleet',
    name: 'fleet',
    component: () => import('./views/FleetManagement.vue')
  },
  {
    path: '/fleet/node/:id',
    name: 'node-details',
    component: () => import('./views/NodeDetails.vue')
  },
  {
    path: '/path',
    name: 'attack path',
    component: () => import('./views/AttackPath.vue')
  },
  {
    path: '/assets',
    name: 'assets',
    component: () => import('./views/Assets.vue')
  },
  {
    path: '/honeytokens',
    name: 'honeytokens',
    component: () => import('./views/Honeytokens.vue')
  },
  {
    path: '/scans',
    name: 'scans',
    component: () => import('./views/Scans.vue')
  },
  {
    path: '/attack',
    name: 'attack navigator',
    component: () => import('./views/Attack.vue')
  },
  {
    path: '/report',
    name: 'reports',
    component: () => import('./views/Report.vue')
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('./views/Settings.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router