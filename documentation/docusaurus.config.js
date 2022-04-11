const path = require('path');

module.exports = {
    title: 'Stronghold',
    url: '/',
    baseUrl: '/',
    themes: ['@docusaurus/theme-classic'],
    plugins: [
        [
            '@docusaurus/plugin-content-docs',
            {
                id: 'stronghold-rs',
                path: path.resolve(__dirname, './docs'),
                routeBasePath: 'stronghold.rs',
                sidebarPath: path.resolve(__dirname, './sidebars.js'),
                editUrl: 'https://github.com/iotaledger/stronghold/edit/dev/',
                remarkPlugins: [require('remark-code-import'), require('remark-import-partial'), require('remark-remove-comments')],
            }
        ],
    ],
    staticDirectories: [path.resolve(__dirname, './static')],
};