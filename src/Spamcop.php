<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;
use PhpMimeMailParser\Parser as MimeParser;

/**
 * Class Spamcop
 * @package AbuseIO\Parsers
 */
class Spamcop extends Parser
{

    /**
     * Create a new Spamcop instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        $reports = [ ];

        if ($this->parsedMail->getHeader('subject') == "[SpamCop] summary report") {
            $this->feedName = 'summary';
            $reports = $this->parseSummaryReport();

        } elseif ($this->parsedMail->getHeader('subject') == "[SpamCop] Alert") {
            $this->feedName = 'alert';
            $reports = $this->parseAlerts();

        } elseif ((strpos($this->parsedMail->getHeader('from'), "@reports.spamcop.net") !== false) &&
                  ($this->arfMail !== false)
        ) {
            $this->feedName = 'spamreport';
            $reports = $this->parseSpamReportArf();

        } elseif ((strpos($this->parsedMail->getHeader('from'), "@reports.spamcop.net") !== false) &&
                  (strpos($this->parsedMail->getMessageBody(), '[ Offending message ]'))
        ) {
            $this->feedName = 'spamreport';
            $reports = $this->parseSpamReportCustom();

        } else {
            $this->warningCount++;

        }

        foreach ($reports as $report) {
            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                // Sanity check
                if ($this->hasRequiredFields($report) === true) {
                    // incident has all requirements met, filter and add!
                    $report = $this->applyFilters($report);

                    if (!empty($report['Spam-URL'])) {
                        $url = $report['Spam-URL'];
                    }
                    if (!empty($report['Reported-URI'])) {
                        $url = $report['Reported-URI'];
                    }

                    if (!empty($url)) {
                        $urlinfo = parse_url($url);

                        if (!empty($urlinfo['host']) && !empty($urlinfo['path'])) {
                            $domain = $urlinfo['host'];
                            $uri = $urlinfo['path'];
                            $this->feedName = 'spamvertizedreport';
                        }
                    }

                    $incident = new Incident();
                    $incident->source      = config("{$this->configBase}.parser.name");
                    $incident->source_id   = false;
                    $incident->ip          = $report['Source-IP'];
                    $incident->domain      = !empty($domain) ? $domain : false;
                    $incident->uri         = !empty($uri) ? $uri : false;
                    $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                    $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                    $incident->timestamp   = strtotime($report['Received-Date']);
                    $incident->information = json_encode($report);

                    $this->incidents[] = $incident;
                }
            }
        }

        return $this->success();
    }

    /**
     * This is a spamcop formatted summery with a multiple incidents
     *
     * @return array $reports
     */
    public function parseSummaryReport()
    {

        $reports = [ ];

        preg_match_all(
            "/^\s*".
            "(?<ip>[a-f0-9:\.]+)\s+".
            "(?<date>\w+\s+\d+\s\d+)h\/".
            "(?<days>\d+)\s+".
            "(?<trap>\d+)\s+".
            "(?<user>\d+)\s+".
            "(?<mole>\d+)\s+".
            "(?<simp>\d+)".
            "/m",
            $this->parsedMail->getMessageBody(),
            $matches,
            PREG_SET_ORDER
        );

        if (is_array($matches) && count($matches) > 0) {
            foreach ($matches as $match) {
                $report = [
                    'Source-IP' => $match['ip'],
                    'Received-Date' => $match['date'] . ':00',
                    'Duration-Days' => $match['days'],
                ];
                foreach (['trap', 'user', 'mole', 'simp'] as $field) {
                    $report[ucfirst($field) ."-Report"] = $match[$field];
                }

                $reports[] = $report;
            }
        }

        return $reports;
    }


    /**
     * This is a spamcop formatted alert with a multiple incidents
     *
     * @return array $reports
     */
    public function parseAlerts()
    {

        $reports = [ ];

        preg_match_all(
            '/\s*(?<ip>[a-f0-9:\.]+)\r?\n?\r\n/',
            $this->parsedMail->getMessageBody(),
            $matches
        );

        $received = $this->parsedMail->getHeaders()['date'];
        if (strtotime(date('d-m-Y H:i:s', strtotime($received))) !== (int)strtotime($received)) {
            $received = date('d-m-Y H:i:s');
        }

        if (is_array($matches) && !empty($matches['ip']) && count($matches['ip']) > 0) {
            foreach ($matches['ip'] as $ip) {
                $reports[] = [
                    'Source-IP' => $ip,
                    'Received-Date' => $received,
                    'Note' => 'A spamtrap hit notification was received.'.
                        ' These notifications do not provide any evidence.'
                ];
            }
        }

        return $reports;

    }


    /**
     * This is a spamcop formatted mail with a single incident
     *
     * @return array $reports
     */
    public function parseSpamReportCustom()
    {

        $reports = [ ];
        $body = $this->parsedMail->getMessageBody();

        // Grab the message part from the body
        preg_match(
            '/(\[ SpamCop V[0-9\.\]\ ]*+)\r?\n(?<message>.*)\r?\n\[ Offending message \]/s',
            $body,
            $matches
        );
        if (!empty($matches['message'])) {
            $report['message'] = $matches['message'];
        }

        // Grab the Evidence from the body
        preg_match(
            '/(\[ Offending message \]*+)\r?\n(?<evidence>.*)/s',
            $body,
            $matches
        );
        if (!empty($matches['evidence'])) {
            $parsedEvidence = new MimeParser();
            $parsedEvidence->setText($matches['evidence']);
            $report['evidence'] = $parsedEvidence->getHeaders();
        }

        // Now parse the data from both extracts
        if (!empty($report['message']) && !empty($report['evidence'])) {
            preg_match(
                '/Email from (?<ip>[a-f0-9:\.]+) \/ (?<date>.*)\r?\n?\r\n/',
                $report['message'],
                $matches
            );

            if (!empty($matches['ip']) && !empty($matches['date'])) {
                $report['Source-IP'] = $matches['ip'];
                $report['Received-Date'] = $matches['date'];

                $reports[] = $report;
            }

            /*
             * Why would you use a single format while you can use different formats huh Spamcop?
             * For spamvertized we need to do some magic to build the report correctly
             *             "(?<mole>\d+)\s+".
             */
            preg_match(
                '/Spamvertised web site:\s'.
                '(?<url>.*)\r?\n?\r\n'.
                '(?<reply>.*)\r?\n?\r\n'.
                '(?<resolved>.*) is (?<ip>.*); (?<date>.*)\r?\n?\r\n'.
                '/',
                $report['message'],
                $matches
            );

            if (!empty($matches['ip']) && !empty($matches['date']) && !empty($matches['url'])) {
                $report['Source-IP'] = $matches['ip'];
                $report['Received-Date'] = $matches['date'];
                $report['Report-URL'] = $matches['reply'];
                $report['Spam-URL'] = $matches['url'];

                $reports[] = $report;
            }

        } else {
            $this->warningCount++;
        }

        return $reports;
    }


    /**
     * This is a ARF mail with a single incident
     *
     * @return array $reports
     */
    public function parseSpamReportArf()
    {
        $reports = [ ];

        //Seriously spamcop? Newlines arent in the CL specifications
        $this->arfMail['report'] = str_replace("\r", "", $this->arfMail['report']);

        preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $regs);
        $report = array_combine($regs[1], $regs[2]);

        //Valueable information put in the body instead of the report, thnx for that Spamcop
        if (strpos($this->arfMail['message'], 'Comments from recipient') !== false) {
            preg_match(
                "/Comments from recipient.*\s]\n(.*)\n\n\nThis/s",
                str_replace(array("\r", "> "), "", $this->arfMail['message']),
                $match
            );
            $report['recipient_comment'] = str_replace("\n", " ", $match[1]);
        }

        // Add the headers from evidence into infoblob
        $parsedEvidence = new MimeParser();
        $parsedEvidence->setText($this->arfMail['evidence']);
        $headers = $parsedEvidence->getHeaders();

        foreach ($headers as $key => $value) {
            if (is_array($value) || is_object(($value))) {
                foreach ($value as $index => $subvalue) {
                    $report['headers']["${key}${index}"] = "$subvalue";
                }
            } else {
                $report['headers']["$key"] = $value;
            }
        }

        /*
         * Sometimes Spamcop has a trouble adding the correct fields. The IP is pretty
         * normal to add. In a last attempt we will try to fetch the IP from the body ourselves
         */
        if (empty($report['Source-IP'])) {
            preg_match(
                "/Email from (?<ip>[a-f0-9:\.]+) \/ " . preg_quote($report['Received-Date']) . "/s",
                $this->arfMail['message'],
                $regs
            );

            if (!empty($regs['ip']) && !filter_var($regs['ip'], FILTER_VALIDATE_IP) === false) {
                $report['Source-IP'] = $regs['ip'];
            }

            preg_match(
                "/from: (?<ip>[a-f0-9:\.]+)\r?\n?\r\n/s",
                $this->parsedMail->getMessageBody(),
                $regs
            );

            if (!empty($regs['ip']) && !filter_var($regs['ip'], FILTER_VALIDATE_IP) === false) {
                $report['Source-IP'] = $regs['ip'];
            }
        }

        $reports[] = $report;

        return $reports;
    }
}
