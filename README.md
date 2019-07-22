# Beagle Security Plugin for Jenkins

This plugin can be used to trigger beagle penetration testing from jenkins

### Prerequisites

Obtain Application Token and User Token from Beagle Dashboard

### Generate your User Token From Beagle User Settings:
  Settings -> Access token -> Generate your new personal access token

![Generate user token](https://beagle-assets.s3.ca-central-1.amazonaws.com/share/usertoken.png)

### Generate your Application Token From Beagle<br></h3>
  Home -> Applications -> Select your application -> Settings -> Application token

![Get application token](https://beagle-assets.s3.ca-central-1.amazonaws.com/share/apptoken.png)


## What is Beagle?

Beagle is an intelligent and holistic platform to make your applications hack-proof. The platform provides continuous and automated Penetration Testing (under human supervision) for organizations, so that they can always stay on top of the cyber threats

In short, Beagle finds out how deep your system can be penetrated. Know it before the hackers do!

* [Beagle Security](https://beaglesecurity.com/) - Visit for more Details!

## Deployment

### Installation of Beagle Security Plugin in Jenkins

1. Login to Jenkins
2. Navigate to `Manage Jenkins` -> `Manage Plugins` 
	* Click on Check Now for retrieving latest plugin information
	* Click on `Available`
	* Search for `Beagle Security`
	* Check `Beagle Security` and Install
	* Restart Jenkins if necessary(Recommended)
	![Install Plugin](/images/1.png)

### Setting up Tokens in Beagle Security
You have to setup APPLICATION TOKEN and USER TOKEN in Jenkins in order to trigger the test
1. Setting up APPLICATION TOKEN
	* `Select project` -> `Configure` -> Select `Build` -> `Add build step` -> Select `Trigger Beagle Penetration Testing` -> Provide `Application Token` and `Save`
	![Global Config](/images/3.png)
	![Global Config](/images/4.png)
2. For USER TOKEN you're provided with two options:
	* Configure Globally, Then by default this USER TOKEN used by the Plugin. To configure it globally follow the steps
		* `Manage Jenkins` -> `Configure System` -> Navigate to `Beagle Security` and Specify your token and `Save`
		![Global Config](/images/2.png)
	* Configure Locally for a project, If this step is done the global configuration will be overrided for the selected project.To configure it per project follow the steps
		* `Select project` -> `Configure` -> Select `Build` -> `Add build step` -> Select `Trigger Beagle Penetration Testing` -> Select `Advanced` -> Provide `User Token` and `Save`
## Authors

* **Beagle Security**

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


