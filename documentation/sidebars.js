/**
 * * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

module.exports = {
    mySidebar: [{
        type: 'doc',
        label: 'Welcome',
        id: 'welcome',
    }, {
        type: 'doc',
        label: 'Getting Started',
        id: 'getting_started',
    }, {
        type: "category",
        label: "Explanations",
        items: [
            {
                type: 'doc',
                id: 'explanations/non-contiguous-data-types',
                label: 'Non-contiguous Data Types'
            },
            {
                type: 'doc',
                id: 'explanations/p2p',
                label: 'Peer to Peer Communication'
            },
            {
                type: 'doc',
                id: 'explanations/procedures',
                label: 'Cryptographic Procedures'
            },
            {
                type: 'doc',
                id: 'explanations/runtime-extensions',
                label: 'Runtime Extensions'
            },
            {
                type: 'doc',
                id: 'explanations/transactional-concurrency',
                label: 'Transactional Memory and Transactional Concurrency'
            },
            {
                type: 'doc',
                id: 'explanations/retrospective',
                label: 'Retrospective'
            },]
    },
        {

            type: "category",
            label: "How Tos",
            items: [
                {
                    type: "category",
                    label: "Command Line Interface (CLI)",
                    items:
                        [
                            'how_tos/cli/running_examples',
                            'how_tos/cli/generate_key_pair',
                            'how_tos/cli/store_read_write',
                            'how_tos/cli/generate_bip39',
                            'how_tos/cli/generate_slip_10',
                            'how_tos/cli/derive_slip_10',
                            'how_tos/cli/create_snapshot',
                            'how_tos/cli/read_snapshot',
                            'how_tos/cli/recover_seed_with_mnemonic',
                        ]
                },
            ]
        },
        {
            type: 'category',
            label: 'Reference',
            items: [
                {
                    type: 'doc',
                    id: 'reference/overview',
                    label: "Overview"
                }, {
                    type: 'category',
                    label: 'Structure',
                    items: [{
                        type: 'doc',
                        id: 'reference/structure/overview',
                        label: 'Overview'
                    }, {
                        type: 'doc',
                        id: 'reference/structure/client',
                        label: 'Client'
                    },
                        {
                            type: 'category',
                            label: 'Engine',
                            items: [
                                {
                                    type: 'doc',
                                    id: 'reference/structure/engine/overview',
                                    label: 'Overview'
                                },

                                {
                                    type: 'doc',
                                    id: 'reference/structure/engine/snapshot',
                                    label: 'Snapshot'
                                },

                                {
                                    type: 'doc',
                                    id: 'reference/structure/engine/vault',
                                    label: 'Vault'
                                },

                                {
                                    type: 'doc',
                                    id: 'reference/structure/engine/store',
                                    label: 'Store'
                                },

                                {
                                    type: 'doc',
                                    id: 'reference/structure/engine/runtime',
                                    label: 'Runtime'
                                },
                            ],
                        },
                        {
                            type: 'doc',
                            id: 'reference/structure/p2p',
                            label: 'P2P Communication'
                        },
                        {
                            type: 'doc',
                            id: 'reference/structure/derive',
                            label: 'Derive'
                        },
                        {
                            type: 'doc',
                            id: 'reference/structure/utils',
                            label: 'Utils'
                        },
                    ]
                },
                {
                    type: 'category',
                    label: 'Specification',
                    items: [{
                        type: 'doc',
                        id: 'reference/specs/overview',
                        label: 'Overview'
                    }, {
                        type: 'doc',
                        id: 'reference/specs/scope',
                        label: 'Scope'
                    }, {
                        type: 'doc',
                        id: 'reference/specs/engineering',
                        label: 'Engineering'
                    },]
                },]
        },
        {
            type: 'doc',
            id: 'contribute',
            label: 'Contribute'
        },
        {
            type: 'link',
            href: 'https://github.com/iotaledger/stronghold.rs',
            label: 'GitHub'
        },
    ]
};
