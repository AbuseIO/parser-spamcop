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
        'report' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
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
