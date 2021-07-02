const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'Stronghold.rs',
  tagline: '',
  url: 'https://stronghold.docs.iota.org/',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  favicon: 'img/logo/favicon.ico',
  organizationName: 'iotaledger', // Usually your GitHub org/user name.
  projectName: 'Stronghold.rs', // Usually your repo name.
  stylesheets: [
    'https://fonts.googleapis.com/css?family=Material+Icons',
    'http://v2202102141633143571.bestsrv.de/assets/css/styles.c88dfa6b.css', //replace this URL
  ],
  themeConfig: {
    navbar: {
      title: 'Stronghold.rs Documentation',
      logo: {
        alt: 'IOTA',
        src: 'static/img/logo/Logo_Swirl_Dark.png',
      },
      items: [{
          type: 'doc',
          docId: 'welcome',
          position: 'left',
          label: 'Documentation',
        },
        //        {to: '/blog', label: 'Blog', position: 'left'},
        {
          href: 'https://github.com/iotaledger/stronghold.rs',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [{
          title: 'Documentation',
          items: [{
              label: 'Welcome',
              to: '/',
            },
            {
              to: 'overview',
              label: 'Overview'
            },
            {
              to: 'structure/overview',
              label: 'Structure'
            },
            {
              to: 'products',
              label: 'Products'
            },
            {
              to: 'specifications/overview',
              label: 'Specification'
            },
            {
              to: 'retrospective/',
              label: 'Retrospective'
            },
            {
              to: 'contribute/',
              label: 'Contribute'
            },
          ],
        },
        {
          title: 'Community',
          items: [{
            label: 'Discord',
            href: 'https://discord.iota.org/',
          }, ],
        },
        {
          title: 'Contribute',
          items: [{
            label: 'GitHub',
            href: 'https://github.com/iotaledger/stronghold.rs',
          }, ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} IOTA Foundation, Built with Docusaurus.`,
    },
    prism: {
      additionalLanguages: ['rust'],
      theme: lightCodeTheme,
      darkTheme: darkCodeTheme,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/',
          // Please change this to your repo.
          editUrl: 'https://github.com/iotaledger/stronghold.rs/tree/dev/docs',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
};