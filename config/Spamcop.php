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
            ],
        ],

        'spamvertizedreport' => [
            'class'     => 'SPAM',
            'type'      => 'Spamvertised web site',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],

        'summary' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
            ],
        ],

        'alert' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
            ],
        ],
    ],
];
