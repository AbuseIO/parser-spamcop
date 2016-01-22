<?php

return [
    'parser' => [
        'name'          => 'Spamcop',
        'enabled'       => true,
        'sender_map'    => [
            '/@reports.spamcop.net/',
            '/summaries@admin.spamcop.net/',
        ],
        'body_map'      => [
            //
        ],
        'aliases'       => [
            //
        ],
    ],

    'feeds' => [
        'spamreport' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
                'Received-Date',
            ],
            'filters'   => [
                'message',
            ]
        ],

        'spamvertizedreport' => [
            'class'     => 'SPAMVERTISED_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
                'Received-Date',
            ],
            'filters'   => [
                'message',
            ]
        ],

        'summary' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
                'Received-Date',
                'Duration-Days',
                'Trap-Report',
                'User-Report',
                'Mole-Report',
                'Simp-Report',
            ],
        ],

        'alert' => [
            'class'     => 'SPAMTRAP',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
                'Received-Date',
                'Note',
            ],
        ],
    ],
];
