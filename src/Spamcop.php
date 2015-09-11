<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Log;
use ReflectionClass;

class Spamcop extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this) . ': Received message from: ' .
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$configBase}.parser.name")
        );

        $events = [ ];

        if($this->parsedMail->getHeader('subject') == "[SpamCop] summary report") {
            $feedName = 'summary';

        } elseif ($this->parsedMail->getHeader('subject') == "[SpamCop] Alert") {
            $feedName = 'alert';

        } elseif (strpos($this->parsedMail->getHeader('subject'), "@reports.spamcop.net") !== false) {
            // This is a ARF mail with a single event
            $feedName = 'report';

            if ($this->arfMail === false) {
                return $this->failed("Detected feed '{$feedName}' should be ARF, but received plain message.");
            }

            //Seriously spamcop? Newlines arent in the CL specifications
            $this->arfMail['report'] = str_replace("\r", "", $this->arfMail['report']);

            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/',$this->arfMail['report'], $regs);
            $fields = array_combine($regs[1],$regs[2]);

        } else {
            return $this->failed("Unabled to detect the report type from this notifier");
        }

        if (empty(config("{$configBase}.feeds.{$feedName}"))) {
            return $this->failed("Detected feed '{$feedName}' is unknown.");
        }

        $columns = array_filter(config("{$configBase}.feeds.{$feedName}.fields"));
        if (count($columns) > 0) {
            foreach ($columns as $column) {
                if (!isset($fields[$column])) {
                    return $this->failed(
                        "Required field ${column} is missing in the report or config is incorrect."
                    );
                }
            }
        }

        if (config("{$configBase}.feeds.{$feedName}.enabled") !== true) {
            return $this->success($events);
        }

        /*
        $event = [
            'source'        => config("{$configBase}.parser.name"),
            'ip'            => $fields['ip'],
            'domain'        => $fields['Domain'],
            'uri'           => $fields['uri'],
            'class'         => config("{$configBase}.feeds.{$feedName}.class"),
            'type'          => config("{$configBase}.feeds.{$feedName}.type"),
            'timestamp'     => strtotime($fields['Date']),
            'information'   => json_encode($fields),
        ];

        $events[] = $event;
        */

        if (empty($events)) {
            return $this->failed(
                config("{$configBase}.parser.name") .
                " was unabled to collect any event(s) from the received email. Either corrupt sample or invalid config"
            );
        }

        return $this->success($events);
    }

}
