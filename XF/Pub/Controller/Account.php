<?php

namespace F4\UserApiKey\XF\Pub\Controller;

use XF;
use XF\Mvc\ParameterBag;
use XF\Mvc\Reply\Exception;

class Account extends XFCP_Account
{
    public function actionApi(): XF\Mvc\Reply\View
    {
        $visitor = XF::visitor();
        $repo = $this->getApiRepo();

        $apiKeys = $repo->findApiKeysForList()
            ->where('user_id', $visitor->user_id)
            ->fetch();

        $allowedScopes = $repo->findApiScopesForList()
            ->where('api_scope_id', $this->options()->f4_uak_allowed_scopes)
            ->fetch();

        $viewParams = [
            'apiKeys' => $apiKeys,
            'allowedScopes' => $allowedScopes
        ];

        $view = $this->view('F4\UserApiKey:Account\Api', 'f4_uak_api', $viewParams);
        return $this->addAccountWrapperParams($view, 'f4_uak');
    }

    public function actionApiClientAdd(): XF\Mvc\Reply\Redirect|XF\Mvc\Reply\View|XF\Mvc\Reply\Error
    {
        $repo = $this->getApiRepo();
        $allowedScopes = $repo->findApiScopesForList()
            ->where('api_scope_id', $this->options()->f4_uak_allowed_scopes)
            ->fetch();

        if ($this->isPost()) {
            if (!$this->captchaIsValid(true)) {
                return $this->error(\XF::phrase('did_not_complete_the_captcha_verification_properly'));
            }

            $input = $this->filter([
                'title' => 'str',
                'scopes' => 'array-str',
            ]);

            $allowedScopes = array_column($allowedScopes->toArray(), 'api_scope_id');

            $invalidScopes = array_filter($input['scopes'], function ($scope) use ($allowedScopes) {
                return !in_array($scope, $allowedScopes);
            });

            if (!empty($invalidScopes)) {
                return $this->error(XF::phrase('f4_uak_invalid_scopes_detected'));
            }

            $apiKey = $this->em()->create('XF:ApiKey');

            $apiKey->bulkSet([
                "api_key" => XF::generateRandomString(32),
                "api_key_hash" => $this->getApiRepo()->getApiKeyHash(XF::generateRandomString(32)),
                "title" => $input['title'],
                "user_id" => XF::visitor()->user_id,
                "scopes" => $input['scopes'],
                "active" => true
            ]);

            $apiKey->save();

            return $this->redirect($this->buildLink('account/api'));
        }

        $viewParams = [
            'allowedScopes' => $allowedScopes
        ];

        $view = $this->view('F4\UserApiKey:Account\ApiClientAdd', 'f4_uak_api_add', $viewParams);
        return $this->addAccountWrapperParams($view, 'f4_uak');
    }

    /**
     * @throws Exception
     */
    public function actionApiDelete(ParameterBag $params)
    {
        $visitor = XF::visitor();

        $apiKey = $this->assertApiKeyExists($params->api_key_id);

        if ($apiKey->user_id != $visitor->user_id) {
            return $this->noPermission();
        }

        $plugin = $this->plugin('XF:Delete');
        return $plugin->actionDelete(
            $apiKey,
            $this->buildLink('account/api/delete', $apiKey),
            $this->buildLink('account/api/edit', $apiKey),
            $this->buildLink('account/api'),
            $apiKey->title
        );
    }

    /**
     * @throws Exception
     */
    protected function assertApiKeyExists($apiKeyId, $with = null, $phraseKey = null): XF\Mvc\Entity\Entity
    {
        return $this->assertRecordExists('XF:ApiKey', $apiKeyId, $with, $phraseKey);
    }

    protected function getApiRepo(): XF\Mvc\Entity\Repository
    {
        return $this->repository('XF:Api');
    }
}