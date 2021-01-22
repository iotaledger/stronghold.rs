
const routes = [
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: '', component: () => import('pages/Index.vue') }
    ]
  },
  {
    path: '/actions',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: 'connect', component: () => import('pages/Connect.vue') },
      { path: 'wipe', component: () => import('pages/Wipe.vue') },
      { path: 'coalition', component: () => import('pages/Coalition.vue') }
    ]
  },
  // Always leave this as last one,
  // but you can also remove it
  {
    path: '*',
    component: () => import('pages/Error404.vue')
  }
]

export default routes
