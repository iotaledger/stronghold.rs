const path = require('path');
const math = require('remark-math');
const katex = require('rehype-katex');

module.exports = {
    plugins: [
        [
            '@docusaurus/plugin-content-docs',
            {
                id: 'stronghold-rs',
                path: path.resolve(__dirname, 'docs'),
                routeBasePath: 'stronghold.rs',
                sidebarPath: path.resolve(__dirname, 'sidebars.js'),
                editUrl: 'https://github.com/iotaledger/stronghold/edit/dev/documentation',
                remarkPlugins: [require('remark-code-import'), require('remark-import-partial'), require('remark-remove-comments'), math],
                rehypePlugins: [katex],
            }
        ],
    ],
    staticDirectories: [path.resolve(__dirname, 'static')],
    stylesheets: [
        {
            href: 'https://cdn.jsdelivr.net/npm/katex@0.13.24/dist/katex.min.css',
            type: 'text/css',
            integrity:
            'sha384-odtC+0UGzzFL/6PNoE8rX/SPcQDXBJ+uRepguP4QkPCm2LBxH3FA3y+fKSiJ+AmM',
            crossorigin: 'anonymous',
        },
    ],
};
