package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static eu.europeana.apikey.util.Tools.nvl;


@Entity
@Table(name = "apikey")
public class ApiKey {
	@Id
//	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "apikey")
	@JsonProperty("apikey")
	private String apiKey;

	@NotNull
	@Size(min = 1, max = 30)
	@Column(name = "privatekey")
	@JsonProperty("privatekey")
	private String privateKey;

	@NotNull
	@Column(name = "registrationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("registrationdate")
	private Date registrationDate;

	@Column(name = "usagelimit")
	@JsonProperty("usagelimit")
	private Long usageLimit;

	@Size(max = 100)
	@Column(name = "website")
	@JsonProperty("website")
	private String website;

	@Column(name = "activationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("activationdate")
	private Date activationDate;

	@Size(max = 255)
	@Column(name = "appname")
	@JsonProperty("appname")
	private String appName;

	@Size(max = 100)
	@Column(name = "company")
	@JsonProperty("company")
	private String company;

	@Size(max = 255)
	@Column(name = "description")
	@JsonProperty("description")
	private String description;

	@NotNull
	@Size(max = 100)
	@Column(name = "email")
	@JsonProperty("email")
	private String email;

	@Size(max = 50)
	@Column(name = "firstname")
	@JsonProperty("firstname")
	private String firstName;

	@Size(max = 50)
	@Column(name = "lastname")
	@JsonProperty("lastname")
	private String lastName;

	@NotNull
	@Size(max = 8)
	@Column(name = "level")
	@JsonProperty("level")
	private String level;

	@Column(name = "deprecationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("deprecationdate")
	private Date deprecationDate;

	@Column(name = "lastaccessdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("lastaccessdate")
	private Date lastaccessDate;

	@NotNull
	@Column(name = "usage")
	@JsonProperty("usage")
	private Long usage;

	public ApiKey() {

	}

	public ApiKey(String apiKey, String privateKey, String email, String level) {
		this.apiKey = apiKey;
		this.privateKey = privateKey;
		this.email = email;
		this.level = level;
		this.registrationDate = new Date();
	}

	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public Date getRegistrationDate() {
		return registrationDate;
	}

	public void setRegistrationDate(Date registrationDate) {
		this.registrationDate = registrationDate;
	}

	public Long getUsageLimit() {
		return usageLimit;
	}

	public void setUsageLimit(Long usageLimit) {
		this.usageLimit = usageLimit;
	}

	public String getWebsite() {
		return website;
	}

	public void setWebsite(String website) {
		this.website = website;
	}

	public Date getActivationDate() {
		return activationDate;
	}

	public void setActivationDate(Date activationDate) {
		this.activationDate = activationDate;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getLevel() {
		return level;
	}

	public void setLevel(String level) {
		this.level = level;
	}

	public Date getDeprecationDate() {
		return deprecationDate;
	}

	public void setDeprecationDate(Date deprecationDate) {
		this.deprecationDate = deprecationDate;
	}

	public Date getLastaccessDate() {
		return lastaccessDate;
	}

	public void setLastaccessDate(Date lastaccesDate) {
		this.lastaccessDate = lastaccessDate;
	}

	public Long getUsage() {
		return usage;
	}

	public void setUsage(Long usage) {
		this.usage = usage;
	}


	@Override
	public String toString() {
		return "ApiKey {" +
				" apiKey = " + apiKey +
				", privateKey = " + nvl(privateKey) +
				", firstName = " + nvl(firstName) +
				", lastName = " + nvl(lastName) +
				", email = " + nvl(email) +
				", level = " + nvl(level) +
				", usage = " + nvl(usage) +
				", usageLimit = " + nvl(usageLimit) +
				", appName = " + nvl(appName) +
				", website = " + nvl(website) +
				", company = " + nvl(company) +
				", description = " + nvl(description) +
				", activationDate = " + nvl(activationDate) +
				", registrationDate = " + nvl(registrationDate) +
				", lastaccessDate = " + nvl(lastaccessDate) +
				", deprecationDate = " + nvl(deprecationDate) +
				" }";
	}

}
