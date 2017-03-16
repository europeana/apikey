package univ.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


@Entity
@Table(name = "apikey")
public class ApiKey {
	@Id
//	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "apikey")
	@JsonProperty("apikey")
	private String apiKey;

	@Size(min = 1, max = 30)
	@Column(name = "privatekey")
	@NotNull
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

	@Size(min = 6, max = 100)
	@Column(name = "website")
	@JsonProperty("website")
	private String website;

	@NotNull
	@Column(name = "activationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("activationdate")
	private Date activationDate;

	@Size(min = 1, max = 255)
	@Column(name = "appname")
	@JsonProperty("appname")
	private String appName;

	@Size(min = 1, max = 100)
	@Column(name = "company")
	@JsonProperty("company")
	private String company;

	@Size(min = 1, max = 255)
	@Column(name = "description")
	@JsonProperty("description")
	private String description;

	@NotNull
	@Size(min = 1, max = 100)
	@Column(name = "email")
	@JsonProperty("email")
	private String email;

	@Size(min = 1, max = 30)
	@Column(name = "firstname")
	@JsonProperty("firstname")
	private String firstName;

	@Size(min = 1, max = 50)
	@Column(name = "lastname")
	@JsonProperty("lastname")
	private String lastName;

	@Size(min = 1, max = 30)
	@Column(name = "level")
	@JsonProperty("level")
	private String level;

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

	@Override
	public String toString() {
		return "ApiKey {" +
				" apiKey = " + apiKey +
				", privateKey = " + privateKey +
				", registrationDate = " + registrationDate.toString() +
				", usageLimit = " + usageLimit.toString() +
				", website = " + website +
				", activationDate = " + activationDate.toString() +
				", appName = " + appName +
				", company = " + company +
				", description = " + description +
				", email = " + email +
				", firstName = " + firstName +
				", lastName = " + lastName +
				", level = " + level +
				" }";
	}
}
